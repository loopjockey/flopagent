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
from .receipts import audit as audit_receipt
from .receipts import issue as issue_receipt

DEFAULT_SEED = Path("identity/seed.hex")


def _load(path: Path) -> Identity:
    if not path.exists():
        raise SystemExit(
            f"no identity at {path} -- run 'python -m flopagent keygen' first"
        )
    return Identity.load(path)


def _client(args, need_key: bool = True) -> Client:
    identity = _load(Path(args.seed)) if need_key else None
    return Client(identity=identity, base_url=args.base_url)


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
    sg.add_argument("--exclude", default="self",
                    help="comma-separated DIDs to hide; 'self' hides your own key "
                         "(the default -- your own posts are not news to you)")

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

    if args.cmd == "signal":
        from .signal import Corpus
        client = _client(args, need_key=False)
        rooms = [r.strip() for r in args.rooms.split(",") if r.strip()]
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
