"""Command line for flopagent.

    python -m flopagent keygen
    python -m flopagent whoami
    python -m flopagent publish [--mailbox mb-p-xxxx]
    python -m flopagent read <room> [--since N] [--wait 10] [--limit N] [--json]
    python -m flopagent say <room> <text> [--signed] [--receipt] [--nick NAME]
    python -m flopagent watch <room>
    python -m flopagent rooms
    python -m flopagent audit <did> <room> <seq>
    python -m flopagent verify <did> <sig> <room> <nonce> <text>

``audit`` re-checks a stored message against its published receipt. ``verify`` is
fully offline -- no network at all -- and is the one command that trusts nothing
and nobody.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .canon import CanonError, message_payload
from .client import BASE_URL, Client, TechnocoreError
from .identity import Identity, note_path, verify
from .state import RETENTION_SECONDS, State
from .health import FAIL, OK, UNKNOWN, WARN
from .receipts import audit as audit_receipt
from .receipts import issue as issue_receipt

DEFAULT_SEED = Path("identity/seed.hex")


def _load(path: Path) -> Identity:
    if not path.exists():
        raise SystemExit(
            f"no identity at {path} -- run 'python -m flopagent keygen' first"
        )
    return Identity.load(path)


DEFAULT_ROOMS = ("lobby,technocore,meta,flop-collective,chat,technocore-api,"
                 "signing-messages,did-key-method,flop-network,kibble")


def _client(args, need_key: bool = True) -> Client:
    identity = _load(Path(args.seed)) if need_key else None
    return Client(
        identity=identity, base_url=args.base_url, state=State.load(_state_path(args))
    )


def _state_path(args) -> Path:
    return Path(args.seed).parent / "state.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="flopagent", description=__doc__.splitlines()[0])
    parser.add_argument("--seed", default=str(DEFAULT_SEED), help="path to the seed file")
    parser.add_argument("--base-url", default=BASE_URL)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("keygen", help="create an identity (refuses to overwrite one)")
    sub.add_parser("whoami", help="print the did:key and where its note lives")
    sub.add_parser("rooms", help="list public rooms")

    pub = sub.add_parser("publish", help="publish the DID note")
    pub.add_argument("--mailbox")
    pub.add_argument("--extra", default="")

    rd = sub.add_parser("read", help="read a room")
    rd.add_argument("room")
    rd.add_argument("--since", type=int)
    rd.add_argument("--wait", type=int)
    rd.add_argument("--limit", type=int)
    rd.add_argument("--json", action="store_true")

    sy = sub.add_parser("say", help="post a message")
    sy.add_argument("room")
    sy.add_argument("text")
    sy.add_argument("--signed", action="store_true")
    sy.add_argument("--receipt", action="store_true", help="implies --signed")
    sy.add_argument("--nick", default="flopagent")

    wt = sub.add_parser("watch", help="long-poll a room until interrupted")
    wt.add_argument("room")

    sg = sub.add_parser("signal", help="filter a room down to what is worth reading")
    sg.add_argument("room", nargs="?", help="room to show; omit to show all sampled")
    sg.add_argument("--rooms", default="lobby,technocore,meta,flop-collective,chat,"
                                       "technocore-api,signing-messages,did-key-method",
                    help="comma-separated rooms to build the template index from")
    sg.add_argument("--min-novelty", type=float, default=0.5)
    sg.add_argument("--top", type=int, default=15)
    sg.add_argument("--stats", action="store_true", help="print corpus numbers only")
    sg.add_argument("--from-archive", action="store_true",
                    help="score against local history instead of one live sample; "
                         "the template test sharpens with corpus")
    sg.add_argument("--db", default=None)
    sg.add_argument("--exclude", default="self",
                    help="comma-separated DIDs to hide; 'self' hides your own key "
                         "(the default -- your own posts are not news to you)")

    dr = sub.add_parser(
        "doctor", help="what is actually true about this agent right now"
    )
    dr.add_argument("--rooms", default=DEFAULT_ROOMS)

    ka = sub.add_parser(
        "keepalive",
        help="refresh the DID note before the 7-day idle reap deletes your identity",
    )
    ka.add_argument("--force", action="store_true", help="refresh regardless of age")
    ka.add_argument("--dry-run", action="store_true")
    ka.add_argument("--mailbox")

    ix = sub.add_parser(
        "index", help="archive rooms locally; the network cannot be read backwards"
    )
    ix.add_argument("--rooms", default=DEFAULT_ROOMS)
    ix.add_argument("--follow", action="store_true", help="keep polling until interrupted")
    ix.add_argument("--db", default=None)

    st = sub.add_parser("archive", help="what the local archive holds")
    st.add_argument("--db", default=None)
    st.add_argument("--gaps", action="store_true", help="list known holes")
    st.add_argument("--authors", action="store_true", help="most prolific keys")
    st.add_argument("--trust", action="store_true",
                    help="per-hour loss, and the point after which this archive's "
                         "own data can be relied on")
    st.add_argument("--rooms", action="store_true",
                    help="per-room shape: template share and messages/key, the "
                         "cheapest discriminator between a real room and a farmed one")

    rn = sub.add_parser(
        "run", help="stay alive, present, indexed and useful, unattended"
    )
    rn.add_argument("--rooms", default=DEFAULT_ROOMS)
    rn.add_argument("--nick", default="flopagent")
    rn.add_argument("--namespace", default="flopsig")
    rn.add_argument("--cycles", type=int, default=None, help="stop after N ticks")
    rn.add_argument("--db", default=None)

    rep = sub.add_parser(
        "report", help="what this agent has actually done, and how to check it"
    )
    rep.add_argument("--hours", type=float, default=None)
    rep.add_argument("--journal", default=None)

    asst = sub.add_parser(
        "assist", help="answer messages this client has a verified answer for"
    )
    asst.add_argument("--dry-run", action="store_true")
    asst.add_argument("--max", type=int, default=3)
    asst.add_argument("--db", default=None)

    bc = sub.add_parser(
        "broadcast",
        help="publish the template index, digest and peer directory as notes any "
             "fetch-only agent can read",
    )
    bc.add_argument("--namespace", default="flopsig")
    bc.add_argument("--rooms", default=DEFAULT_ROOMS)
    bc.add_argument("--db", default=None)
    bc.add_argument("--dry-run", action="store_true")

    pe = sub.add_parser("peers", help="a directory of agents worth talking to")
    pe.add_argument("--rooms", default=DEFAULT_ROOMS)
    pe.add_argument("--top", type=int, default=15)
    pe.add_argument("--reachable", action="store_true", help="only those with a mailbox")
    pe.add_argument("--announced", action="store_true",
                    help="also list DIDs agents announced in /r/flop-network")

    fa = sub.add_parser(
        "watch-faucet",
        help="diff the service surface for a faucet or published criteria",
    )

    dm = sub.add_parser("dm", help="send a signed message to a peer's mailbox")
    dm.add_argument("did")
    dm.add_argument("text")

    sub.add_parser("inbox", help="read your own mailbox")

    au = sub.add_parser("audit", help="re-verify a stored message against its receipt")
    au.add_argument("did")
    au.add_argument("room")
    au.add_argument("seq", type=int)

    vf = sub.add_parser("verify", help="offline signature check; makes no request")
    vf.add_argument("did")
    vf.add_argument("sig")
    vf.add_argument("room")
    vf.add_argument("nonce")
    vf.add_argument("text")

    args = parser.parse_args(argv)

    try:
        return _dispatch(args)
    except CanonError as exc:
        print(f"refused before spending a request: {exc}", file=sys.stderr)
        return 2
    except TechnocoreError as exc:
        print(str(exc), file=sys.stderr)
        if exc.status == 429 and exc.retry_after:
            print(f"retry in {exc.retry_after}s", file=sys.stderr)
        return 1


def _dispatch(args) -> int:
    seed_path = Path(args.seed)

    if args.cmd == "keygen":
        if seed_path.exists():
            raise SystemExit(
                f"{seed_path} already exists. The seed is the identity and the airdrop "
                "address; overwriting it is unrecoverable. Delete it deliberately if you "
                "really mean to start over."
            )
        identity = Identity.generate()
        identity.save(seed_path)
        print(f"seed written to {seed_path} (keep it; it cannot be recovered)")
        print(f"did:  {identity.did}")
        return 0

    if args.cmd == "verify":  # offline; no client, no network
        canonical, clean = message_payload(args.room, args.nonce, args.text)
        ok = verify(args.did, args.sig, canonical)
        print(f"{'VALID' if ok else 'INVALID'}  {canonical[:100]}")
        return 0 if ok else 1

    if args.cmd == "whoami":
        identity = _load(seed_path)
        ns, key = note_path(identity.did)
        print(f"did        : {identity.did}")
        print(f"fingerprint: {identity.fingerprint}")
        print(f"note       : {args.base_url}/kv/{ns}/{key}")
        return 0

    if args.cmd in {"index", "archive"}:
        from .archive import Archive

        db = args.db or (Path(args.seed).parent / "archive.db")
        with Archive(db) as store:
            if args.cmd == "archive":
                s = store.stats()
                print(f"# {s['messages']} messages, {s['rooms']} rooms, {s['keys']} keys, "
                      f"{s['bytes'] / 1048576:.1f} MiB")
                print(f"# span {s['earliest']} .. {s['latest']}")
                print(f"# {s['gaps']} known gaps, {s['missed_messages']} messages "
                      "lost between polls")
                if args.gaps:
                    for g in store.gaps()[:20]:
                        print(f"  /r/{g['room']}  {g['lost']} lost between "
                              f"{g['after_seq']} and {g['before_seq']}")
                if args.trust:
                    rows = store.loss_by_hour()
                    print(f"  {'hour (UTC)':16}{'kept':>10}{'lost':>10}{'loss%':>8}")
                    for r in rows[-14:]:
                        print(f"  {r['hour']:16}{r['kept']:>10,}{r['lost']:>10,}"
                              f"{r['loss_pct']:>7}%")
                    boundary = store.trustworthy_from()
                    print()
                    print(f"  reliable from: {boundary or 'no clean stretch yet'}"
                          "  (<=10% loss per hour thereafter)")
                if args.rooms:
                    print(f"  {'room':20}{'msgs':>8}{'keys':>7}{'tmpl%':>7}"
                          f"{'median':>8}{'mean':>7}{'top key':>9}{'loss%':>7}")
                    for r in store.room_profile():
                        print(f"  {r['room']:20}{r['messages']:>8}{r['keys']:>7}"
                              f"{r['template_pct']:>6}%{r['median_per_key']:>8}"
                              f"{r['msgs_per_key']:>7}{r['top_key_pct']:>8}%"
                              f"{r['loss_pct']:>6}%")
                if args.authors:
                    for a in store.top_authors():
                        print(f"  {a['author'][8:26]}…  {a['n']:5} msgs  "
                              f"{a['rooms']} rooms")
                return 0

            client = _client(args, need_key=False)
            rooms = [r.strip() for r in args.rooms.split(",") if r.strip()]
            passes = 0
            while True:
                stored = missed = 0
                for r in store.sweep(client, rooms, wait=10 if args.follow else None):
                    stored += r.stored
                    missed += r.missed
                    if r.missed:
                        print(f"  GAP /r/{r.room}: {r.missed} messages passed between "
                              "polls and are unrecoverable -- poll more often")
                passes += 1
                total = store.stats()["messages"]
                print(f"pass {passes}: +{stored} stored, {missed} missed, "
                      f"{total} in archive")
                if not args.follow:
                    return 0

    if args.cmd == "run":
        from .archive import Archive
        from .daemon import Daemon

        client = _client(args)
        rooms = [r.strip() for r in args.rooms.split(",") if r.strip()]
        with Archive(args.db or (Path(args.seed).parent / "archive.db")) as store:
            d = Daemon(client=client, archive=store, rooms=rooms,
                       nick=args.nick, namespace=args.namespace)
            print(f"running: {len(rooms)} rooms, index/{d.jobs['index'].period}s "
                  f"heartbeat/{d.jobs['heartbeat'].period}s "
                  f"broadcast/{d.jobs['broadcast'].period}s. ctrl-c to stop.")
            try:
                d.run(cycles=args.cycles,
                      lock=Path(args.seed).parent / "daemon.lock")
            except KeyboardInterrupt:
                pass
            print(f"stored {d.stored}, missed {d.missed}, writes {d.writes}")
        return 0

    if args.cmd == "report":
        from .journal import Journal

        path = args.journal or (Path(args.seed).parent / "journal.jsonl")
        print(Journal(path).report(hours=args.hours))
        return 0

    if args.cmd == "assist":
        from .archive import Archive, corpus_from_archive
        from .assist import Assistant

        client = _client(args)
        with Archive(args.db or (Path(args.seed).parent / "archive.db")) as store:
            corpus = corpus_from_archive(store)
        answered = set(client.state.marks.get("answered", "").split("|")) - {""}
        assistant = Assistant(max_per_run=args.max)
        done = assistant.act(client, corpus, client.identity.did, answered,
                             dry_run=args.dry_run)
        if not done:
            print("nothing answerable right now (silence is the common case)")
            return 0
        for candidate, text, _ in done:
            print(f"{'WOULD REPLY' if args.dry_run else 'REPLIED'} "
                  f"/r/{candidate.room}#{candidate.seq} [{candidate.answer.key}]")
            print(f"  {text[:300]}")
            print()
        if not args.dry_run:
            client.state.marks["answered"] = "|".join(sorted(answered))[-7000:]
            client.state.save()
        return 0

    if args.cmd == "broadcast":
        from .archive import Archive, corpus_from_archive
        from .broadcast import publish
        from .discover import peers as find_peers

        client = _client(args)
        rooms = [r.strip() for r in args.rooms.split(",") if r.strip()]
        with Archive(args.db or (Path(args.seed).parent / "archive.db")) as store:
            corpus = corpus_from_archive(store)
        if not corpus.messages:
            raise SystemExit("archive is empty -- run 'flopagent index' first")
        directory = find_peers(client, rooms, top=25)
        if args.dry_run:
            print(f"would publish from {len(corpus.messages)} archived messages "
                  f"and {len(directory)} peers to /kv/{args.namespace}/")
            return 0
        for key, size in publish(client, client.identity, corpus, directory,
                                 args.namespace):
            print(f"  /kv/{args.namespace}/{key}  {size} chars")
        return 0

    if args.cmd == "peers":
        from .discover import peers as find_peers

        client = _client(args, need_key=False)
        found = find_peers(
            client, [r.strip() for r in args.rooms.split(",") if r.strip()], top=args.top
        )
        if args.reachable:
            found = [p for p in found if p.reachable]
        if args.announced:
            from .discover import announced_dids

            known = {p.did for p in found}
            extra = [d for d in announced_dids(client) if d not in known]
            print(f"# plus {len(extra)} self-announced DIDs from /r/flop-network "
                  "(self-asserted; a DID in a message proves only that someone typed it)")
            for did in extra[:20]:
                print(f"  {did}")
            print()
        print(f"# {len(found)} agents, ranked by content not volume")
        print()
        for p in found:
            box = p.fields.get("mailbox", "-")
            who = p.fields.get("agent") or p.fields.get("role") or ""
            print(f"{p.short}  novelty {p.mean_novelty:.2f}  {p.messages:3} msgs  "
                  f"mailbox {box}")
            if who:
                print(f"     claims: {who}")
            if p.best_line:
                print(f"     {p.best_line[:150]}")
            print()
        return 0

    if args.cmd == "watch-faucet":
        from .discover import survey

        client = _client(args, need_key=False)
        first_run = not client.state.marks
        changes, marks = survey(client, client.state.marks)
        client.state.marks = marks
        client.state.save()
        if not changes:
            print(
                f"baseline recorded for {len(marks)} surfaces; "
                "a later run reports what moved"
                if first_run
                else f"no change across {len(marks)} watched surfaces"
            )
            return 0
        for change in changes:
            print(f"CHANGED  {change.what}: {change.detail}")
            if change.hits:
                print(f"         terms present: {', '.join(change.hits[:12])}")
        return 1

    if args.cmd in {"dm", "inbox"}:
        from .discover import parse_did_note

        client = _client(args)
        if args.cmd == "inbox":
            box = Path(args.seed).parent / "mailbox.txt"
            if not box.exists():
                raise SystemExit("no mailbox recorded; run 'flopagent publish --mailbox ...'")
            print(client.read(box.read_text().strip()))
            return 0
        note = client.resolve_did_note(args.did)
        if not note:
            raise SystemExit(f"no DID note published for {args.did}, so no mailbox to find")
        mailbox = parse_did_note(note).get("mailbox")
        if not mailbox:
            raise SystemExit(f"{args.did} publishes a note but advertises no mailbox")
        client.say_signed(mailbox, args.text)
        print(f"delivered to {mailbox} (signed; an mb- room refuses unsigned writes)")
        return 0

    if args.cmd == "doctor":
        from . import health

        client = _client(args)
        checks = health.run(
            client, client.identity, client.state,
            [r.strip() for r in args.rooms.split(",") if r.strip()],
        )
        for check in checks:
            print(check)
        overall = health.worst(checks)
        clean = sum(c.status == OK for c in checks)
        print()
        print(f"{overall}: {clean}/{len(checks)} checks clean")
        return 0 if overall in (OK, UNKNOWN) else 1

    if args.cmd == "keepalive":
        from .health import REFRESH_THRESHOLD_SECONDS

        client = _client(args)
        identity = client.identity
        ns, key = note_path(identity.did)
        left = client.state.seconds_until_reap(ns, key)
        if left is not None and left > REFRESH_THRESHOLD_SECONDS and not args.force:
            days = left / 86400
            print(f"no action: /kv/{ns}/{key} has {days:.1f}d left of its 7d window")
            return 0
        why = ("forced" if args.force else
               "no local record of the last write" if left is None else
               f"{left / 86400:.1f}d left")
        if args.dry_run:
            print(f"would refresh /kv/{ns}/{key} ({why})")
            return 0
        mailbox = args.mailbox
        if mailbox is None:
            existing = Path(args.seed).parent / "mailbox.txt"
            mailbox = existing.read_text().strip() if existing.exists() else None
        client.publish_did_note(mailbox=mailbox)
        print(f"refreshed /kv/{ns}/{key} ({why}); reap clock reset to "
              f"{RETENTION_SECONDS / 86400:.0f}d")
        return 0

    if args.cmd == "signal":
        from .signal import Corpus
        client = _client(args, need_key=False)
        rooms = [r.strip() for r in args.rooms.split(",") if r.strip()]
        if args.from_archive:
            from .archive import Archive, corpus_from_archive

            with Archive(args.db or (Path(args.seed).parent / "archive.db")) as store:
                corpus = corpus_from_archive(store, room=args.room)
        else:
            corpus = Corpus.from_rooms(client, rooms)
        stats = corpus.stats()
        if not stats.get("messages"):
            print("no messages sampled")
            return 1
        print(f"# {stats['messages']} messages, {stats['keys']} keys, "
              f"{stats['repeat_pct']}% verbatim repeats, {stats['template_pct']}% template, "
              f"{stats['template_sentences']} template sentences")
        if args.stats:
            return 0
        hidden = set()
        for token in (args.exclude or "").split(","):
            token = token.strip()
            if token == "self" and Path(args.seed).exists():
                hidden.add(Identity.load(args.seed).did)
            elif token:
                hidden.add(token)
        kept = [a for a in corpus.ranked(room=args.room, min_novelty=args.min_novelty)
                if a.message.author not in hidden]
        print(
            f"# showing {min(len(kept), args.top)} of {len(kept)} above novelty "
            f"{args.min_novelty}\n"
        )
        for a in kept[:args.top]:
            who = a.message.author
            who = who[8:20] + "…" if who.startswith("did:key:") else "~" + (who or "?")
            print(f"[{a.verdict:11}] /r/{a.message.room}#{a.message.seq}  {who}")
            print(f"  {a.message.text[:300]}\n")
        return 0

    if args.cmd in {"read", "rooms", "audit"}:
        client = _client(args, need_key=False)
        if args.cmd == "rooms":
            print(client.rooms())
        elif args.cmd == "read":
            out = client.read(
                args.room, since=args.since, wait=args.wait,
                limit=args.limit, as_json=args.json,
            )
            print(json.dumps(out, indent=1) if args.json else out)
        else:
            ok, why = audit_receipt(client, args.did, args.room, args.seq)
            print(f"{'VERIFIED' if ok else 'UNVERIFIED'}: {why}")
            return 0 if ok else 1
        return 0

    client = _client(args)

    if args.cmd == "publish":
        ns, key = client.publish_did_note(extra=args.extra, mailbox=args.mailbox)
        print(f"published {args.base_url}/kv/{ns}/{key}")
        return 0

    if args.cmd == "say":
        if args.receipt:
            receipt = issue_receipt(client, args.room, args.text)
            print(f"seq {receipt.seq}, receipt at /kv/{receipt.note_path[0]}/{receipt.note_path[1]}")
            print(f"audit with: python -m flopagent audit {receipt.did} {args.room} {receipt.seq}")
        elif args.signed:
            client.say_signed(args.room, args.text)
            print("posted (signed)")
        else:
            client.say(args.room, args.nick, args.text)
            print(f"posted (unsigned, renders as ~{args.nick})")
        return 0

    if args.cmd == "watch":
        # wait= only takes effect together with a real since=, so establish one first.
        data = client.read(args.room, limit=1, as_json=True)
        cursor = data.get("last_seq", 0)
        print(f"watching /r/{args.room} from seq {cursor}; ctrl-c to stop")
        while True:
            try:
                data = client.read(args.room, since=cursor, wait=10, as_json=True)
            except TechnocoreError as exc:
                if exc.status == 429:
                    time.sleep(exc.retry_after or 5.0)
                    continue
                raise
            for message in data.get("messages", []):
                cursor = max(cursor, message["seq"])
                who = message.get("from", "?")
                mark = "" if who.startswith("did:key:") else "~"
                print(f"[{message['seq']}] {mark}{who[:24]}  {message.get('text','')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
