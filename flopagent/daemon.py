"""``flopagent run``: keep an agent alive, present, indexed and useful, unattended.

Five jobs an agent has to do forever and will not do by hand:

* **stay alive** -- a note idle for seven days is deleted, and nothing warns you;
* **stay present** -- write the heartbeat convention the manual documents, so
  peers polling a room can tell a live agent from an abandoned key;
* **keep indexing** -- the read window ends at the tail, so history not collected
  now is unreachable later, permanently;
* **keep the feed fresh** -- a stale template index is worse than none, because
  readers filter against frames that have moved on;
* **watch for the faucet** -- the one confirmed airdrop mechanism, unannounced.

**On volume.** This generates real, continuous protocol traffic, and every write
it makes is one the protocol documents or one that carries new information: a
heartbeat (`/llms.txt` CONVENTIONS), a DID-note refresh, a feed republish. It does
not post to rooms. That is a deliberate limit, not an oversight -- three quarters
of this network's traffic is already boilerplate, it is trivially detectable, and
adding to it would both pollute the rooms and discredit the template index this
same client publishes.

Rate limits are per IP: reads and writes refill separately, and replies carry a
``# budget:`` footer once a bucket drops below a quarter. This backs off on that
footer rather than waiting for a 429, and honours the delay in a 429 body when one
arrives anyway.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field

from pathlib import Path

from .archive import Archive
from .canon import CanonError, check_name
from .client import Client, TechnocoreError
from .health import REFRESH_THRESHOLD_SECONDS
from .identity import note_path
from .journal import Journal
from .pacing import Pacer

#: How often each job runs, in seconds. `index` ticks fast but polls only the
#: rooms the pacer says are due, so the tick rate is a floor on responsiveness
#: rather than a per-room cost: a 9/s room gets a short period and a room seeing
#: two messages in twenty minutes gets a long one. Everything else is slow.
INDEX_EVERY = 5
HEARTBEAT_EVERY = 300
BROADCAST_EVERY = 3 * 3600
FAUCET_EVERY = 900
KEEPALIVE_EVERY = 3600
#: Fast, but narrow: it only ever considers messages that arrived since the last
#: pass, and the per-run and per-room caps are unchanged. Speed matters because a
#: question falls outside the addressable 200-message window in seconds on a busy
#: room -- a correct answer twenty minutes later replies to something nobody can
#: still reach. Most passes correctly find nothing to say.
ASSIST_EVERY = 25
#: Answering queries runs on the same cadence as assist: a query is a question
#: someone is waiting on, and the addressable window is seconds on a busy room.
SERVE_EVERY = 25
#: Capacity sampling. Cheap (a handful of namespace listings) and slow, because
#: the point is a trend across hours rather than a reading. It exists so that a
#: prediction this client published is checked by this client, automatically,
#: including when the prediction turns out to be wrong.
CAPACITY_EVERY = 900
#: Mailbox acquisition. The room table is full, so the claim is a poll against an
#: eviction queue rather than a one-shot; it also carries the beacon that keeps a
#: room already won from being reclaimed. Cheap: at most one write per pass, and
#: usually none.
MAILBOX_EVERY = 900

#: ``GET /rooms`` publishes both totals and both caps in its header lines:
#: ``# N of TOTAL rooms (cap CAP, ...)`` and ``# notes TOTAL of CAP (...)``.
#: This used to be extrapolated from 16 ``did-`` shards against a hardcoded
#: cap, which measured one namespace family against the whole store and
#: compared it to a number the operator has since raised twice. Both halves
#: were wrong, in opposite directions. Nothing is extrapolated now.
ROOMS_HEAD = re.compile(r"^# \d+ of (\d+) rooms \(cap (\d+)", re.M)
NOTES_HEAD = re.compile(r"^# notes (\d+) of (\d+)", re.M)


#: The room read lane serves at most this many records newer than ``since``,
#: so a room running at R messages/second keeps a record fetchable for
#: ``READ_LIMIT / R`` seconds and not one moment longer. There is no backfill
#: lane, so what falls out of it is gone.
READ_LIMIT = 200


def window_line(rates: dict, captured: dict, read_limit: int = READ_LIMIT) -> str:
    """One line per measured room: rate, the window it implies, what I captured.

    Rooms with no measured rate are omitted rather than reported as zero: an
    unpolled room and a silent one are indistinguishable from here, and a
    fabricated "infinite window" is the kind of number a reader would act on.
    """
    parts = []
    for room, rate in sorted(rates.items(), key=lambda kv: -kv[1]):
        if rate <= 0:
            continue
        seconds = read_limit / rate
        part = f"{room} {rate:.1f} msg/s, window ~{seconds:.0f}s"
        if room in captured:
            part += f", I captured {captured[room]:.1f}%"
        parts.append(part)
    if not parts:
        return ""
    # Without this, the capture column reads as a property of the room. It is
    # not: a quiet room I poll every 200s can lose a larger share than a fast
    # one I poll every 2s, and two of them here do exactly that.
    parts.append(
        f"window = {read_limit} / rate, the read lane's cap on records newer "
        "than `since`; capture is what my own poll interval achieved against "
        "it, not a property of the room; no backfill lane, so a record past "
        "the window is unreachable permanently"
    )
    return " | ".join(parts)


@dataclass
class Job:
    name: str
    period: float
    last: float = 0.0
    runs: int = 0
    errors: int = 0

    def due(self, now: float) -> bool:
        return now - self.last >= self.period

    def retry_in(self, seconds: float, now: float) -> None:
        """Come back sooner than the period, without changing the period.

        For a job that ran but could not do all of its work yet. Never used to
        make a job faster in general -- the periods are the pacing.
        """
        self.last = min(self.last, now - self.period + seconds)


@dataclass
class Daemon:
    client: Client
    archive: Archive
    rooms: list[str]
    nick: str = "flopagent"
    namespace: str = "flopsig"
    jobs: dict[str, Job] = field(default_factory=dict)
    stored: int = 0
    missed: int = 0
    writes: int = 0
    journal: Journal = field(default_factory=Journal)
    _assistant: object = None
    _claimer: object = None
    #: ``(room, seq)`` of everything the last index pass brought in.
    _fresh: set = field(default_factory=set)
    #: ``(note_total, when)`` from the previous capacity sample.
    _capacity_last: tuple | None = None
    #: Latest human-readable capacity reading, republished in the signal feed.
    _capacity_line: str | None = None
    #: Per-DID query budget, so the service cannot be turned into a flood.
    quota: object = field(default_factory=lambda: __import__(
        "flopagent.serve", fromlist=["Quota"]).Quota())
    #: Per-room cadence. One interval cannot serve a 9/s room and a 2-per-20min
    #: room at once, and under-polling the fast one destroys history rather than
    #: delaying it.
    pacer: Pacer = field(default_factory=Pacer)

    def __post_init__(self) -> None:
        check_name(self.nick, "nick")
        for name, period in (
            ("index", INDEX_EVERY), ("heartbeat", HEARTBEAT_EVERY),
            ("faucet", FAUCET_EVERY), ("keepalive", KEEPALIVE_EVERY),
            ("assist", ASSIST_EVERY), ("serve", SERVE_EVERY),
            ("capacity", CAPACITY_EVERY),
            ("mailbox", MAILBOX_EVERY),
            ("broadcast", BROADCAST_EVERY),
        ):
            self.jobs[name] = Job(name, period)

    # ---- pacing ----------------------------------------------------------

    def _throttled(self) -> float:
        """Seconds to pause based on the budget footer, before a 429 happens.

        The footer only appears once a bucket is under a quarter full, so seeing
        it at all is the signal to slow down; the numbers refine by how much.
        """
        worst = 1.0
        for left, total in self.client.budget.values():
            if total:
                worst = min(worst, left / total)
        return 0.0 if worst >= 0.25 else (0.25 - worst) * 40

    # ---- jobs ------------------------------------------------------------

    def do_index(self) -> str:
        due = self.pacer.due(self.rooms)
        if not due:
            self._fresh = set()
            return "none due"
        stored = missed = 0
        before = {r: self.archive.cursor_for(r) or 0 for r in due}
        for result in self.archive.sweep(self.client, due):
            stored += result.stored
            missed += result.missed
            self.pacer.observed(result.room, result.stored, result.missed)
        # Remember exactly what is new, so assist can answer it while it is still
        # inside the window a reader can address.
        self._fresh = {
            (r, row["seq"])
            for r in due
            for row in self.archive.db.execute(
                "SELECT seq FROM messages WHERE room = ? AND seq > ?", (r, before[r])
            ).fetchall()
        }
        self.stored += stored
        self.missed += missed
        if stored:
            self.journal.record(
                "archive",
                f"captured {stored} messages across {len(self.rooms)} rooms"
                + (f", lost {missed} to polling slower than the room" if missed else ""),
                "flopagent archive",
                stored=stored, missed=missed,
            )
        note = f"+{stored} from {len(due)}/{len(self.rooms)} rooms"
        if missed:
            note += f", {missed} LOST"
        return f"{note}  [{self.pacer.summary()}]"

    def do_heartbeat(self) -> str:
        """The presence convention from the manual, verbatim.

        ``/kv/<room>/hb-<nick>/set/<seq you last saw>``. A peer is live if the
        note moved recently. There is no server-side expiry, so a stale heartbeat
        means "unknown", never "dead" -- and this writes the *seq actually seen*,
        so the note is evidence of reading rather than a bare liveness ping.
        """
        written = 0
        for room in self.rooms:
            seq = self.archive.cursor_for(room)
            if seq is None:
                continue
            try:
                self.client.write_note(room, f"hb-{self.nick}", str(seq))
                written += 1
                self.writes += 1
            except (TechnocoreError, CanonError):
                continue
        return f"{written} rooms"

    def do_faucet(self) -> str:
        from .discover import survey

        changes, marks = survey(self.client, self.client.state.marks)
        self.client.state.marks = marks
        self.client.state.save()
        if not changes:
            return "no change"
        for change in changes:
            print(f"    !! {change.what}: {change.detail} {change.hits[:8]}")
            self.journal.record(
                "note", f"service surface changed: {change.what} - {change.detail}",
                f"curl https://technocore.chat{change.what}"
                if change.what.startswith("/") else "",
                hits=change.hits[:8],
            )
        return f"{len(changes)} CHANGED"

    def do_keepalive(self) -> str:
        identity = self.client.identity
        if identity is None:
            return "no key"
        ns, key = note_path(identity.did)
        left = self.client.state.seconds_until_reap(ns, key)
        if left is not None and left > REFRESH_THRESHOLD_SECONDS:
            return f"{left / 86400:.1f}d left"
        self.client.publish_did_note(mailbox=self._mailbox())
        self.writes += 1
        self.journal.record(
            "keepalive",
            f"refreshed /kv/{ns}/{key}; identity would otherwise have been deleted",
            f"flopagent doctor",
        )
        return "refreshed"

    def do_assist(self) -> str:
        """Answer messages there is a verified answer for. Usually: nothing."""
        from .archive import corpus_from_archive
        from .assist import Assistant

        state = self.client.state
        answered = set(state.marks.get("answered", "").split("|")) - {""}
        corpus = corpus_from_archive(self.archive)
        # Refresh room quality each pass, so the ranking follows the network.
        self.assistant.room_quality = {
            r["room"]: r["msgs_per_key"] for r in self.archive.room_profile()
        }
        done = self.assistant.act(self.client, corpus, self.client.identity.did,
                                  answered, fresh=self._fresh or None)
        if not done:
            return "nothing answerable"
        state.marks["answered"] = "|".join(sorted(answered))[-7000:]
        state.save()
        self.writes += len(done) * 2          # message + receipt
        did = self.client.identity.did
        for candidate, _, reply_seq in done:
            print(f"    helped /r/{candidate.room}#{candidate.seq} "
                  f"[{candidate.answer.key}]")
            self.journal.record(
                "helped",
                f"answered /r/{candidate.room}#{candidate.seq} with "
                f"{candidate.answer.key} ({candidate.answer.finding})",
                f"flopagent audit {did} {candidate.room} {reply_seq}",
                room=candidate.room, target_seq=candidate.seq,
                answer=candidate.answer.key,
            )
        return f"{len(done)} answered"

    def do_serve(self) -> str:
        """Answer `FLOPAGENT: ...` queries from other agents, in their room.

        Only signed queries: an answer about "your key" means nothing if anyone
        can ask as anyone. Only fresh messages, because a query is a question
        somebody is waiting on and the window it can be read in is seconds.
        """
        from .archive import corpus_from_archive
        from .serve import parse, respond

        if not self._fresh:
            return "no new messages"
        rows = []
        for room, seq in self._fresh:
            row = self.archive.db.execute(
                "SELECT room, seq, author, text FROM messages WHERE room=? AND seq=?",
                (room, seq)).fetchone()
            if row and row["author"] and row["author"].startswith("did:key:"):
                rows.append(row)
        queries = [(r, parse(r["text"] or "")) for r in rows]
        queries = [(r, q) for r, q in queries if q]
        if not queries:
            return "no queries"

        corpus = corpus_from_archive(self.archive, limit=60000)
        served = 0
        for row, (verb, argument) in queries:
            asker = row["author"]
            if asker == self.client.identity.did:
                continue                       # never answer ourselves
            if not self.quota.allow(asker):
                continue                       # silently, so the limit is not a megaphone
            reply = respond(self.client, self.archive, corpus, verb, argument, asker)
            short = asker[len("did:key:"):][:9]
            try:
                self.client.say_signed(row["room"], f"@{short} {reply}"[:4000])
            except (TechnocoreError, CanonError):
                continue
            served += 1
            self.writes += 1
            self.journal.record(
                "helped",
                f"answered a FLOPAGENT: {verb} query from {short} in /r/{row['room']}",
                f"flopagent read {row['room']}",
            )
        return f"{served} answered" if served else "none allowed"

    def do_capacity(self) -> str:
        """Read the served totals, and check my own prediction against them.

        FINDINGS 27 put the global note cap 1.0-2.1 days out. A prediction
        nobody checks is worth nothing, so this checks it -- and the first
        version of this check was itself wrong: it sampled ``did-`` shards,
        multiplied by 256, and divided by a hardcoded 327,680. The service
        publishes both figures exactly on ``/rooms``, so the estimate is now
        the measurement, and it is falsified by the record rather than
        defended by argument.

        A *falling* total is the 7-day reap becoming visible, which is the one
        thing that could flatten the curve.
        """
        import time as _t

        try:
            body = self.client.rooms()
        except TechnocoreError:
            return "unreadable"
        notes = NOTES_HEAD.search(body)
        if not notes:
            return "unreadable"
        total, cap = int(notes.group(1)), int(notes.group(2))
        if not cap:
            return "unreadable"
        occupancy = 100 * total / cap

        note = f"{total:,} of {cap:,} notes, {occupancy:.1f}% of cap"
        self._capacity_line = (
            f"notes {total:,}/{cap:,} {occupancy:.1f}% of the global note cap"
        )
        rooms = ROOMS_HEAD.search(body)
        if rooms:
            r_total, r_cap = int(rooms.group(1)), int(rooms.group(2))
            if r_cap:
                # Both caps, because either can be the one that refuses the next
                # write, and the room cap is what took the mailbox (FINDINGS 35).
                r_pct = 100 * r_total / r_cap
                note += f"; {r_total:,} of {r_cap:,} rooms, {r_pct:.1f}%"
                self._capacity_line += (
                    f" | rooms {r_total:,}/{r_cap:,} {r_pct:.1f}% of the room cap"
                )

        previous = self._capacity_last
        rate = None
        shrinking = False
        if previous:
            was, when = previous
            elapsed = _t.time() - when
            shrinking = total < was
            if elapsed > 60:
                rate = (total - was) / elapsed * 3600
        self._capacity_last = (total, _t.time())

        if rate is not None:
            headroom = cap - total
            days = headroom / rate / 24 if rate > 0 else None
            note += f", {rate:+,.0f}/h"
            note += f", ~{days:.1f}d left" if days else ", not growing"
            self._capacity_line += (
                f" | rate {rate:+,.0f} notes/h"
                + (f" | ~{days*24:.1f}h to the cap at that rate" if days
                   else " | not growing")
                + (" | the total fell, so the 7-day reap is now outpacing growth"
                   if shrinking else " | the total did not fall, so the 7-day"
                   " reap is not outpacing growth")
                + " | both figures served by GET /rooms; exact, not sampled"
            )
            self.journal.record(
                "note",
                f"capacity: {occupancy:.1f}% of the note cap, {rate:+,.0f} notes/hour"
                + (f", ~{days:.1f} days remaining" if days else ", not growing")
                + (", total fell (reap visible)" if shrinking else
                   ", total did not fall (reap not outpacing growth)"),
                "curl -s https://technocore.chat/rooms | grep '^# notes'",
                occupancy_pct=round(occupancy, 2),
                notes_per_hour=round(rate),
                note_total=total,
                note_cap=cap,
                shrinking=shrinking,
            )
        return note

    def do_mailbox(self) -> str:
        """Keep queueing for an address peers can actually reach.

        The service is at its room cap, so the mailbox the onboarding docs tell
        every agent to publish cannot be created on demand -- but rooms are
        reclaimed continuously, so the slot arrives eventually and this is what
        is waiting when it does. Winning it is published straight away: an
        address held but not advertised reaches nobody, which is the state this
        is trying to leave.
        """
        status = self.claimer.attempt(self.client)
        won = self.claimer.held
        if won and won not in self.rooms:
            # Every pass, not only the one that wins it: after a restart the
            # address is already advertised, and keying this off the publish
            # branch would drop the mailbox out of the indexed set for good.
            self.rooms.append(won)         # or nothing sent there is ever read
        if won and self.claimer.advertised != won:
            self.client.publish_did_note(mailbox=won)
            self.claimer.advertised = won
            self.writes += 1
            self.journal.record(
                "mailbox",
                f"claimed /r/{won} and advertised it in the DID note; peers had "
                f"no reachable address before this",
                "flopagent doctor",
            )
        if status.startswith(("claimed", "beacon")):
            self.writes += 1
        return status

    def do_broadcast(self) -> str:
        import time as _time

        from .archive import corpus_from_archive
        from .broadcast import publish
        from .discover import peers as find_peers

        corpus = corpus_from_archive(self.archive)
        if len(corpus.messages) < 200:
            return f"only {len(corpus.messages)} archived, waiting"
        directory = find_peers(self.client, self.rooms, top=25)
        # The pacer already measures every room's rate to schedule itself, and
        # the archive already knows what those polls captured. Neither number
        # left this process before; together they are the read window, which is
        # what a reader needs to choose an interval.
        rates = {name: pace.rate for name, pace in self.pacer.rooms.items()}
        captured = {row["room"]: row["captured_pct"]
                    for row in self.archive.capture_profile()}
        windows = window_line(rates, captured)
        parts = publish(self.client, self.client.identity, corpus, directory,
                        self.namespace, capacity=self._capacity_line,
                        windows=windows)
        if not windows and "broadcast" in self.jobs:
            # The first broadcast after a start runs before any room has been
            # polled twice, so no rate exists yet and the window part is
            # omitted rather than faked. Waiting a full period to publish it
            # would mean a restart costs three hours of the one part that
            # cannot be derived from anything else in the feed.
            self.jobs["broadcast"].retry_in(300, _time.time())
        self.writes += len(parts)
        self.journal.record(
            "broadcast",
            f"republished {len(parts)} notes from {len(corpus.messages)} archived "
            "messages, readable by any fetch-only agent",
            f"curl https://technocore.chat/kv/{self.namespace}/index",
            parts=[k for k, _ in parts],
        )
        return f"{len(parts)} notes from {len(corpus.messages)} messages"

    @property
    def assistant(self):
        from .assist import Assistant

        if self._assistant is None:
            self._assistant = Assistant(max_per_run=2, max_per_room_per_run=1)
        return self._assistant

    @property
    def claimer(self):
        from .mailbox import MailboxClaimer

        if self._claimer is None:
            self._claimer = MailboxClaimer(Path("identity"))
        return self._claimer

    def _mailbox(self) -> str | None:
        return self.claimer.held

    # ---- loop ------------------------------------------------------------

    def tick(self, now: float | None = None) -> list[str]:
        """Run whatever is due. Returns one line per job that ran."""
        now = time.time() if now is None else now
        lines: list[str] = []
        for name in ("index", "heartbeat", "faucet", "keepalive", "assist",
                     "serve", "capacity", "mailbox", "broadcast"):
            job = self.jobs[name]
            if not job.due(now):
                continue
            try:
                detail = getattr(self, f"do_{name}")()
                job.runs += 1
            except TechnocoreError as exc:
                job.errors += 1
                detail = f"HTTP {exc.status}"
                if exc.status == 429 and exc.retry_after:
                    time.sleep(min(exc.retry_after, 60))
            except (CanonError, ValueError) as exc:
                job.errors += 1
                detail = str(exc)[:80]
            job.last = now
            lines.append(f"{name}: {detail}")
        return lines

    def run(self, cycles: int | None = None, sleep: float = 5.0,
            lock: Path | None = None) -> None:
        """Loop until interrupted, or for ``cycles`` ticks when testing.

        A second instance is refused. Two daemons do not merely duplicate the
        heartbeat writes: each holds its own in-memory state for hours, and the
        stale one erases the fresher one's record of what it has already answered
        -- which cost a duplicate public reply before this existed. `State.save`
        now merges rather than clobbers, so the lock is the second line of
        defence rather than the only one.
        """
        if lock is not None:
            if lock.exists():
                age = time.time() - lock.stat().st_mtime
                if age < 600:
                    raise SystemExit(
                        f"another daemon holds {lock} (touched {age:.0f}s ago). "
                        "Stop it first, or delete the lock if it died."
                    )
            lock.write_text(str(os.getpid()), encoding="utf-8")
        count = 0
        while cycles is None or count < cycles:
            for line in self.tick():
                print(f"  {line}")
            pause = self._throttled()
            if pause:
                print(f"  pacing: budget low, sleeping {pause:.0f}s")
                time.sleep(pause)
            if lock is not None:
                lock.touch()          # liveness, so a crashed daemon frees it
            time.sleep(sleep)
            count += 1
