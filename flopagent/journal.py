"""An append-only record of what this agent actually did, for whoever runs it.

An unattended agent is opaque. It writes to a public network for hours, and the
operator's only alternatives are to read a scrolling log or to trust it. Neither
is a report.

So every action that plausibly produced value appends one line here, and the
guiding rule is that **an entry must be checkable by someone who does not trust
this program**. A reply carries the command that re-verifies its signature. A
published note carries its URL. Archived messages carry the count and, just as
importantly, the count that was *lost*. Entries that cannot be checked are
recorded as claims and labelled as such, rather than dressed up as results.

Nothing here is scored, ranked or weighted into a total. A number this program
assigned to its own usefulness would be exactly the kind of unfounded authority
its own template index warns readers about, and an operator reading a summary
should be looking at what was done, not at a self-awarded grade.

Append-only JSONL: one crash-safe line per action, cheap to tail, trivial to
diff, and readable without this program.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PATH = Path("identity/journal.jsonl")

#: What kinds of entry exist, and the one-line gloss used in the report. Adding a
#: kind means deciding how it is verified, which is the point of the exercise.
KINDS = {
    "helped": "answered an agent's question with a verified finding",
    "outreach": "delivered a message to a peer's mailbox",
    "broadcast": "published the signal feed for fetch-only agents",
    "finding": "established a protocol fact by reproduction",
    "keepalive": "refreshed the identity before the idle reap",
    "archive": "captured history the API can no longer serve back",
    "correction": "corrected something this agent had previously got wrong",
    "note": "an observation with no external artefact",
}


@dataclass
class Entry:
    kind: str
    what: str
    #: A command or URL a sceptic can run. Empty means "claim, not result".
    evidence: str = ""
    at: float = field(default_factory=time.time)
    extra: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({
            "at": round(self.at, 3),
            "kind": self.kind,
            "what": self.what,
            "evidence": self.evidence,
            **self.extra,
        }, sort_keys=True)


class Journal:
    """Append-only. Never rewritten, so a crash truncates at most one line."""

    def __init__(self, path: str | os.PathLike[str] = DEFAULT_PATH) -> None:
        self.path = Path(path)

    def record(self, kind: str, what: str, evidence: str = "", **extra) -> Entry:
        if kind not in KINDS:
            raise ValueError(f"unknown journal kind {kind!r}; add it to KINDS")
        entry = Entry(kind=kind, what=what, evidence=evidence, extra=extra)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            # A crash can leave the final line unterminated. Appending straight
            # onto it splices two records into one unparseable line and loses
            # BOTH -- the torn one and the good one that follows. Close the wound
            # first, so a crash costs exactly the record it interrupted.
            if self._needs_newline():
                handle.write("\n")
            handle.write(entry.to_json() + "\n")
        return entry

    def _needs_newline(self) -> bool:
        """True if the file ends mid-line, i.e. a previous write was interrupted."""
        try:
            if self.path.stat().st_size == 0:
                return False
            with self.path.open("rb") as handle:
                handle.seek(-1, os.SEEK_END)
                return handle.read(1) not in (b"\n", b"\r")
        except (OSError, ValueError):
            return False

    def entries(self, since: float | None = None) -> list[dict]:
        if not self.path.exists():
            return []
        rows = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue  # a torn final line from a crash; skip it, do not fail
            if since is None or row.get("at", 0) >= since:
                rows.append(row)
        return rows

    # ---- reporting -------------------------------------------------------

    def report(self, hours: float | None = None) -> str:
        """A plain-text summary for the operator. Facts and how to check them."""
        since = None if hours is None else time.time() - hours * 3600
        rows = self.entries(since)
        if not rows:
            window = "ever" if hours is None else f"in the last {hours:g}h"
            return f"nothing recorded {window}."

        span = f"the last {hours:g}h" if hours else "all recorded activity"
        first = time.strftime("%Y-%m-%d %H:%MZ", time.gmtime(rows[0]["at"]))
        last = time.strftime("%Y-%m-%d %H:%MZ", time.gmtime(rows[-1]["at"]))
        out = [f"flopagent report — {span}", f"  {first} .. {last}, {len(rows)} entries", ""]

        by_kind: dict[str, list[dict]] = {}
        for row in rows:
            by_kind.setdefault(row["kind"], []).append(row)

        # Ordered by how much a reader should care, not alphabetically.
        for kind in ("helped", "finding", "correction", "outreach", "broadcast",
                     "archive", "keepalive", "note"):
            entries = by_kind.get(kind)
            if not entries:
                continue
            out.append(f"{kind.upper()}  ({len(entries)}) — {KINDS[kind]}")
            for row in entries[-8:]:
                stamp = time.strftime("%d %H:%MZ", time.gmtime(row["at"]))
                out.append(f"  {stamp}  {row['what']}")
                if row.get("evidence"):
                    out.append(f"            verify: {row['evidence']}")
            if len(entries) > 8:
                out.append(f"  … and {len(entries) - 8} earlier")
            out.append("")

        unverifiable = [r for r in rows if not r.get("evidence")]
        if unverifiable:
            out.append(
                f"{len(unverifiable)} of {len(rows)} entries carry no evidence "
                "command. Those are claims, not results."
            )
        return "\n".join(out)
