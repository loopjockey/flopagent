"""A local archive of rooms, because the network cannot be read backwards.

technocore.chat is not merely ephemeral, it is *already* unreadable. `since=`
opens a window and `limit` keeps the newest 200 of it, and there is no `at=`,
`before=` or `until=` (docs/FINDINGS.md §8). So the window a reader can open
always ends at the tail: in a busy room, anything more than 200 messages back is
unreachable **while it still exists**. After that the ring drops it at ~10 MiB,
and notes reap after seven idle days.

The consequence is that nobody can study this network over time. A one-shot
sample of the newest 200 messages per room is the *only* view the API offers, and
every measurement taken that way is a snapshot of the present with no past to
compare against.

An archive is the only fix, and it has to be built forwards: poll each room from
the last sequence seen and keep what arrives. This cannot recover history from
before it started running, and it never pretends to.

**Gaps are recorded, not hidden.** If more than `limit` messages land between two
polls, the missed ones are gone for good -- the manual says a reply whose
`first_seq` exceeds your `since + 1` means you missed lines, and that is exactly
what this detects and writes down. An archive that silently contains holes is
worse than one that admits them, because the holes become invisible errors in
every statistic computed from it.

SQLite from the standard library: one file, real queries, no dependency, and
crash-safe under the default journal.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .client import Client, TechnocoreError

DEFAULT_DB = Path("identity/archive.db")

#: The server's read cap. Polling must stay inside this or messages are lost.
READ_LIMIT = 200

_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    room   TEXT NOT NULL,
    seq    INTEGER NOT NULL,
    ts     TEXT,
    author TEXT,
    text   TEXT,
    nonce  INTEGER,
    PRIMARY KEY (room, seq)
);
CREATE INDEX IF NOT EXISTS messages_author ON messages(author);
CREATE INDEX IF NOT EXISTS messages_room_ts ON messages(room, ts);

-- A hole we know about: everything strictly between these two is lost for good.
CREATE TABLE IF NOT EXISTS gaps (
    room        TEXT NOT NULL,
    after_seq   INTEGER NOT NULL,
    before_seq  INTEGER NOT NULL,
    noticed_at  REAL NOT NULL,
    PRIMARY KEY (room, after_seq, before_seq)
);

CREATE TABLE IF NOT EXISTS cursors (
    room     TEXT PRIMARY KEY,
    last_seq INTEGER NOT NULL,
    polled_at REAL NOT NULL
);
"""


@dataclass
class PollResult:
    room: str
    stored: int = 0
    missed: int = 0
    last_seq: int = 0
    error: str = ""


class Archive:
    """Append-only local history of the rooms you choose to follow."""

    def __init__(self, path: str | Path = DEFAULT_DB) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(_SCHEMA)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "Archive":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- ingest ----------------------------------------------------------

    def cursor_for(self, room: str) -> int | None:
        row = self.db.execute(
            "SELECT last_seq FROM cursors WHERE room = ?", (room,)
        ).fetchone()
        return row["last_seq"] if row else None

    def poll(self, client: Client, room: str, wait: int | None = None) -> PollResult:
        """Fetch everything new in ``room`` and store it. Returns what happened.

        A first poll has no cursor, so it takes the newest window and starts
        there -- it cannot reach further back, and saying so is the point.
        """
        result = PollResult(room=room)
        since = self.cursor_for(room)
        try:
            data = client.read(
                room, since=since,
                wait=wait if since is not None else None,
                limit=READ_LIMIT, as_json=True,
            )
        except TechnocoreError as exc:
            result.error = f"{exc.status}"
            return result

        messages = data.get("messages", [])
        if not messages:
            result.last_seq = since or 0
            return result

        first_seq = messages[0].get("seq", 0)
        # The manual's own gap test: a window that starts later than the next
        # sequence we expected means records passed between polls and are gone.
        if since is not None and first_seq > since + 1:
            self.db.execute(
                "INSERT OR IGNORE INTO gaps VALUES (?,?,?,?)",
                (room, since, first_seq, time.time()),
            )
            result.missed = first_seq - since - 1

        rows = [
            (room, m.get("seq"), m.get("ts"), m.get("from"), m.get("text"), m.get("nonce"))
            for m in messages
            if m.get("seq") is not None
        ]
        before = self.db.total_changes
        self.db.executemany(
            "INSERT OR IGNORE INTO messages VALUES (?,?,?,?,?,?)", rows
        )
        result.stored = self.db.total_changes - before
        result.last_seq = max(m["seq"] for m in messages)
        self.db.execute(
            "INSERT INTO cursors VALUES (?,?,?) ON CONFLICT(room) DO UPDATE SET "
            "last_seq = excluded.last_seq, polled_at = excluded.polled_at",
            (room, result.last_seq, time.time()),
        )
        self.db.commit()
        return result

    #: How many back-to-back polls one room may take to drain its backlog before
    #: the sweep moves on. Bounded so a firehose cannot starve the other rooms or
    #: burn the whole read budget in one place.
    MAX_DRAIN = 12

    def drain(self, client: Client, room: str, wait: int | None = None) -> PollResult:
        """Poll ``room`` repeatedly until it stops returning full windows.

        **This cannot recover a backlog, and it is important not to believe it
        can.** The window `since` opens always *ends at the tail*, and `limit`
        keeps the newest 200 of it. So a reader 1000 messages behind gets the
        newest 200 and the other 800 are unreachable -- not slow to fetch,
        unreachable, because no parameter addresses them (FINDINGS.md §8). Falling
        behind loses data permanently.

        What draining actually buys is smaller and still worth having: after the
        first poll jumps to the tail, more messages have usually landed *during*
        that round-trip, and a second poll collects them instead of leaving them
        to be skipped next cycle. It keeps a caught-up archiver caught up.

        The only real defence is polling often enough never to fall 200 behind. At
        `/r/lobby`'s observed ~50 messages/second that is roughly every three
        seconds; `--follow` with a ten-second wait is not enough for that room, and
        the gap counter is what tells you so.
        """
        total = PollResult(room=room)
        for attempt in range(self.MAX_DRAIN):
            # wait= only on the first pass: once draining, there is no waiting to do.
            result = self.poll(client, room, wait=wait if attempt == 0 else None)
            total.stored += result.stored
            total.missed += result.missed
            total.last_seq = result.last_seq or total.last_seq
            total.error = result.error
            if result.error or result.stored < READ_LIMIT:
                break
        return total

    def sweep(self, client: Client, rooms: list[str], wait: int | None = None):
        """One pass over every room, draining each. Yields a :class:`PollResult`."""
        for room in rooms:
            yield self.drain(client, room, wait=wait)

    # ---- query -----------------------------------------------------------

    def stats(self) -> dict[str, object]:
        db = self.db
        total = db.execute("SELECT COUNT(*) c FROM messages").fetchone()["c"]
        rooms = db.execute("SELECT COUNT(DISTINCT room) c FROM messages").fetchone()["c"]
        keys = db.execute(
            "SELECT COUNT(DISTINCT author) c FROM messages WHERE author LIKE 'did:key:%'"
        ).fetchone()["c"]
        span = db.execute("SELECT MIN(ts) a, MAX(ts) b FROM messages").fetchone()
        gaps = db.execute(
            "SELECT COUNT(*) c, COALESCE(SUM(before_seq - after_seq - 1), 0) m FROM gaps"
        ).fetchone()
        return {
            "messages": total,
            "rooms": rooms,
            "keys": keys,
            "earliest": span["a"],
            "latest": span["b"],
            "gaps": gaps["c"],
            "missed_messages": gaps["m"],
            "bytes": self.path.stat().st_size if self.path.exists() else 0,
        }

    def messages(self, room: str | None = None, author: str | None = None,
                 since_ts: str | None = None, limit: int = 100000) -> list[sqlite3.Row]:
        clauses, params = [], []
        if room:
            clauses.append("room = ?"); params.append(room)
        if author:
            clauses.append("author = ?"); params.append(author)
        if since_ts:
            clauses.append("ts >= ?"); params.append(since_ts)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        return self.db.execute(
            f"SELECT room, seq, ts, author, text FROM messages {where} "
            f"ORDER BY ts LIMIT ?", params
        ).fetchall()

    def top_authors(self, limit: int = 20) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT author, COUNT(*) n, COUNT(DISTINCT room) rooms "
            "FROM messages WHERE author LIKE 'did:key:%' "
            "GROUP BY author ORDER BY n DESC LIMIT ?", (limit,)
        ).fetchall()

    def gaps(self) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT room, after_seq, before_seq, before_seq - after_seq - 1 lost "
            "FROM gaps ORDER BY lost DESC"
        ).fetchall()


def corpus_from_archive(archive: Archive, room: str | None = None, limit: int = 50000):
    """Build a :class:`flopagent.signal.Corpus` from stored history.

    The template test sharpens with corpus: a frame can only be called a template
    once the index has seen other keys using it, so an archive spanning days finds
    what a single 200-message sample cannot.
    """
    from .signal import Corpus, Message

    corpus = Corpus()
    for row in archive.messages(room=room, limit=limit):
        corpus.add(Message(row["room"], row["seq"], row["author"] or "", row["text"] or ""))
    return corpus
