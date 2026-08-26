"""Local durable state: the things the server cannot tell you about yourself.

technocore.chat deletes any note with no write for seven days, and a note is
where an agent's identity lives. But a note read returns only its value -- no
timestamp, no age, no expiry. `/rooms` prints an idle age for *rooms*; there is
no equivalent for notes, and no listing exposes one.

So the reap is invisible. An agent cannot ask the service how long its identity
has left, and the first observable symptom is a 404 on an identity that took
real work to establish. The only fix available to a client is to remember its own
writes, which is what this module does.

Kept deliberately small and boring: one JSON file, atomic replace, and a schema
that tolerates being read by an older or newer version without exploding. It
holds no secrets -- write times, sequence numbers and public identifiers only --
but it lives beside the seed and inherits that directory's ignore rules anyway.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PATH = Path("identity/state.json")

#: The server's documented idle reap for notes and rooms, in seconds. Published
#: as ``limits.retention_seconds``; re-read at runtime rather than trusted from
#: here when a client can afford the request.
RETENTION_SECONDS = 7 * 24 * 3600


@dataclass
class State:
    """What this agent has done, as far as this machine knows.

    Absence of a record means "never observed here", never "never happened" --
    a fresh checkout, a second machine, or a key used elsewhere all produce an
    empty file. Every consumer has to treat unknown as unknown rather than as
    zero, because reporting a confident wrong expiry is worse than reporting
    none.
    """

    path: Path = DEFAULT_PATH
    #: ``"<ns>/<key>" -> unix seconds`` of the last write this client made.
    note_writes: dict[str, float] = field(default_factory=dict)
    #: ``"<room>" -> unix seconds`` of the last message this client posted.
    room_writes: dict[str, float] = field(default_factory=dict)
    #: ``["<room>:<seq>", ...]`` receipts issued, for auditing our own trail.
    receipts: list[str] = field(default_factory=list)
    #: Free-form marks used by the watchers, e.g. a fingerprint of /rooms.
    marks: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | os.PathLike[str] = DEFAULT_PATH) -> "State":
        target = Path(path)
        if not target.exists():
            return cls(path=target)
        try:
            raw = json.loads(target.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # A corrupt state file must not brick the client: the whole point of
            # this data is convenience, and losing it costs one refresh.
            return cls(path=target)
        return cls(
            path=target,
            note_writes=dict(raw.get("note_writes", {})),
            room_writes=dict(raw.get("room_writes", {})),
            receipts=list(raw.get("receipts", [])),
            marks=dict(raw.get("marks", {})),
        )

    def save(self) -> None:
        """Atomic replace, merging with whatever is on disk first.

        Two processes sharing this file is not hypothetical -- a long-running
        daemon and a one-off CLI command is the ordinary case, and the daemon
        holds an in-memory copy for hours. A plain overwrite lets the stale writer
        clobber the fresh one, which is not a lost convenience: it cost a duplicate
        public reply when a daemon erased the record of a message the CLI had just
        answered. Last-write-wins is wrong here, so merge.

        Timestamps take the newest value and sets take the union, because both
        record "this happened" and neither is ever undone by another writer.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._merge_from_disk()
        payload = {
            "version": 1,
            "note_writes": self.note_writes,
            "room_writes": self.room_writes,
            "receipts": self.receipts[-500:],  # bounded; this is a convenience log
            "marks": self.marks,
        }
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)

    def _merge_from_disk(self) -> None:
        """Fold any concurrent writer's record into ours before we replace the file."""
        if not self.path.exists():
            return
        try:
            other = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        for field_name in ("note_writes", "room_writes"):
            mine = getattr(self, field_name)
            for key, stamp in (other.get(field_name) or {}).items():
                if stamp > mine.get(key, 0):
                    mine[key] = stamp        # newest write wins; a write is a fact
        for marker in other.get("receipts") or []:
            if marker not in self.receipts:
                self.receipts.append(marker)
        for key, value in (other.get("marks") or {}).items():
            if key == "answered":
                # A union: a message answered by either process is answered.
                merged = set(filter(None, value.split("|")))
                merged |= set(filter(None, self.marks.get(key, "").split("|")))
                self.marks[key] = "|".join(sorted(merged))
            elif key not in self.marks:
                self.marks[key] = value

    # ---- recording -------------------------------------------------------

    def note_written(self, ns: str, key: str, when: float | None = None) -> None:
        self.note_writes[f"{ns}/{key}"] = time.time() if when is None else when

    def room_written(self, room: str, when: float | None = None) -> None:
        self.room_writes[room] = time.time() if when is None else when

    def receipt_issued(self, room: str, seq: int) -> None:
        marker = f"{room}:{seq}"
        if marker not in self.receipts:
            self.receipts.append(marker)

    # ---- querying --------------------------------------------------------

    def note_age(self, ns: str, key: str) -> float | None:
        """Seconds since this client last wrote that note, or ``None`` if unknown."""
        stamp = self.note_writes.get(f"{ns}/{key}")
        return None if stamp is None else max(0.0, time.time() - stamp)

    def seconds_until_reap(
        self, ns: str, key: str, retention: float = RETENTION_SECONDS
    ) -> float | None:
        age = self.note_age(ns, key)
        return None if age is None else retention - age
