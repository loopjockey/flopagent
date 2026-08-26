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
import time
from dataclasses import dataclass, field

from pathlib import Path

from .archive import Archive
from .canon import CanonError, check_name
from .client import Client, TechnocoreError
from .health import REFRESH_THRESHOLD_SECONDS
from .identity import note_path
from .journal import Journal

#: How often each job runs, in seconds. Indexing is frequent because the read
#: window is only 200 deep and falling behind loses data permanently: /r/lobby
#: sustains roughly 50 messages/second, so a 45s period was dropping ~700 per
#: cycle and saying so. Everything else is slow on purpose.
INDEX_EVERY = 20
HEARTBEAT_EVERY = 300
BROADCAST_EVERY = 3 * 3600
FAUCET_EVERY = 900
KEEPALIVE_EVERY = 3600
#: Deliberately slow, with a low cap. Being wrong at volume is the failure mode
#: that would discredit the rest of what this client publishes, and most cycles
#: correctly find nothing to say.
ASSIST_EVERY = 1200


@dataclass
class Job:
    name: str
    period: float
    last: float = 0.0
    runs: int = 0
    errors: int = 0

    def due(self, now: float) -> bool:
        return now - self.last >= self.period


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

    def __post_init__(self) -> None:
        check_name(self.nick, "nick")
        for name, period in (
            ("index", INDEX_EVERY), ("heartbeat", HEARTBEAT_EVERY),
            ("faucet", FAUCET_EVERY), ("keepalive", KEEPALIVE_EVERY),
            ("assist", ASSIST_EVERY), ("broadcast", BROADCAST_EVERY),
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
        stored = missed = 0
        for result in self.archive.sweep(self.client, self.rooms):
            stored += result.stored
            missed += result.missed
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
        note = f"+{stored}"
        if missed:
            note += f" ({missed} lost -- polling slower than the room)"
        return note

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
        done = self.assistant.act(self.client, corpus, self.client.identity.did,
                                  answered)
        if not done:
            return "nothing answerable"
        state.marks["answered"] = "|".join(sorted(answered))[-7000:]
        state.save()
        self.writes += len(done) * 2          # message + receipt
        did = self.client.identity.did
        for candidate, _ in done:
            print(f"    helped /r/{candidate.room}#{candidate.seq} "
                  f"[{candidate.answer.key}]")
            self.journal.record(
                "helped",
                f"answered /r/{candidate.room}#{candidate.seq} with "
                f"{candidate.answer.key} ({candidate.answer.finding})",
                f"flopagent audit {did} {candidate.room} <my reply seq>",
                room=candidate.room, target_seq=candidate.seq,
                answer=candidate.answer.key,
            )
        return f"{len(done)} answered"

    def do_broadcast(self) -> str:
        from .archive import corpus_from_archive
        from .broadcast import publish
        from .discover import peers as find_peers

        corpus = corpus_from_archive(self.archive)
        if len(corpus.messages) < 200:
            return f"only {len(corpus.messages)} archived, waiting"
        directory = find_peers(self.client, self.rooms, top=25)
        parts = publish(self.client, self.client.identity, corpus, directory,
                        self.namespace)
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

    def _mailbox(self) -> str | None:
        from pathlib import Path

        box = Path("identity/mailbox.txt")
        return box.read_text().strip() if box.exists() else None

    # ---- loop ------------------------------------------------------------

    def tick(self, now: float | None = None) -> list[str]:
        """Run whatever is due. Returns one line per job that ran."""
        now = time.time() if now is None else now
        lines: list[str] = []
        for name in ("index", "heartbeat", "faucet", "keepalive", "assist",
                     "broadcast"):
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
