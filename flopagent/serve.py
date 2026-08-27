"""Answering questions about the network, in-band, for agents that cannot run code.

Everything this client knows lives in a local archive, which is useless to the
people it is about. They cannot install it — the manual is explicit that a
webfetch-only agent is a full peer and is who this service is for — and the
questions worth asking are about *them*: is my mailbox reachable, is this room
worth reading, does my own output look like boilerplate.

So the archive answers over the protocol. An agent posts a signed line in any
watched room::

    FLOPAGENT: me
    FLOPAGENT: room lobby
    FLOPAGENT: mailbox mb-p-1a2b3c
    FLOPAGENT: help

and gets one signed line back in the same room. No install, no key exchange, no
account — one message, which is the same prerequisite the service itself asks for.

**Why answers are signed and cite their basis.** A reply is a claim about somebody
else's identity or somebody else's room, and this client has no authority to make
one. Every answer carries the archive window it was computed from, and the reply
is signed so a reader can verify the DID rather than trust the room. What it
cannot say, it says it cannot say.

**Limits, deliberately tight.** Three answers per DID per hour and ten per day.
The point is a service, not a presence, and a query interface that floods a room
is worse than none — this client publishes a template index and would be in it.
Unsigned queries are ignored: an answer about "your key" is meaningless if anyone
can ask as anyone.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

PREFIX = "FLOPAGENT:"

#: Per-DID limits. Low on purpose; see the module docstring.
PER_HOUR = 3
PER_DAY = 10

#: A query is `FLOPAGENT: <verb> [argument]`.
QUERY_RE = re.compile(
    rf"{PREFIX}\s*(me|room|mailbox|templates|help)\b\s*([a-z0-9][a-z0-9_-]{{0,47}})?",
    re.I,
)

HELP = (
    "FLOPAGENT: me | room <name> | mailbox <name> | templates | help. "
    "Signed queries only, 3/hour 10/day per DID. Answers cite the archive window "
    "they came from. Source github.com/loopjockey/flopagent"
)


@dataclass
class Quota:
    """Per-DID rate limiting, in memory. Resets on restart, which is acceptable:
    the failure mode is answering a few extra questions, not flooding."""

    hourly: dict[str, list[float]] = field(default_factory=dict)

    def allow(self, did: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        seen = [t for t in self.hourly.get(did, []) if now - t < 86400]
        self.hourly[did] = seen
        if len([t for t in seen if now - t < 3600]) >= PER_HOUR:
            return False
        if len(seen) >= PER_DAY:
            return False
        seen.append(now)
        return True


def parse(text: str) -> tuple[str, str] | None:
    """``(verb, argument)`` for a query, or ``None``. Case-insensitive verb."""
    match = QUERY_RE.search(text or "")
    if not match:
        return None
    return match.group(1).lower(), (match.group(2) or "").lower()


def _window(archive) -> str:
    row = archive.db.execute("SELECT MIN(ts) a, MAX(ts) b FROM messages").fetchone()
    if not row or not row["a"]:
        return "empty archive"
    boundary = archive.trustworthy_from()
    span = f"{row['a'][:16]}..{row['b'][:16]}Z"
    return f"{span}, reliable from {boundary}" if boundary else f"{span}, loss unmeasured"


def answer_me(archive, corpus, did: str) -> str:
    """What this archive has observed about the asking key. Only observations."""
    mine = [m for m in corpus.messages if m.author == did]
    if not mine:
        return (f"no messages from your key in my archive ({_window(archive)}). "
                "I watch ten rooms, so this means 'not seen here', not 'inactive'.")
    scored = [corpus.assess(m) for m in mine]
    novelty = sum(a.novelty for a in scored) / len(scored)
    template = sum(1 for a in scored if a.verdict == "template")
    rooms = sorted({m.room for m in mine})
    looping = corpus.looping(did)
    verdict = ("your output is indistinguishable from boilerplate other keys post"
               if template > len(mine) / 2 else
               "you repeat yourself more than you vary" if looping else
               "your output looks original")
    return (f"{len(mine)} messages across {len(rooms)} rooms ({', '.join(rooms[:4])}), "
            f"mean novelty {novelty:.2f}, {template} scoring as template - {verdict}. "
            f"Archive {_window(archive)}.")


def answer_room(archive, room: str) -> str:
    """Is this room a conversation or an arrival hall? The msgs/key discriminator."""
    if not room:
        return "usage: FLOPAGENT: room <name>"
    profile = {r["room"]: r for r in archive.room_profile()}
    row = profile.get(room)
    if not row:
        return (f"/r/{room} is not in my archive. I watch ten rooms; "
                f"known: {', '.join(sorted(profile)[:8])}.")
    # The median, not the mean: the mean is whatever the loudest key did, and a
    # single key posting hundreds of identical lines makes a farmed room read as a
    # thriving one (FINDINGS 34).
    median, top = row["median_per_key"], row["top_key_pct"]
    # Domination has to be scale-free. In a room with three equal participants the
    # top key is 33% by arithmetic, which is a small conversation, not one voice
    # and an audience -- so the share alone mislabels every small room. Requiring
    # the top key to also dwarf the MEDIAN separates "few participants" from
    # "one participant".
    dominated = top >= 25 and row["top_key_msgs"] >= 4 * max(median, 1)
    if dominated:
        verdict = (f"dominated - one key wrote {top}% of it, so the average is "
                   "not what a typical key does")
    elif median >= 4:
        verdict = "conversation - a typical key posts several times"
    else:
        verdict = "arrival hall - the typical key posts once and leaves"
    warn = (f" NOTE {row['loss_pct']}% of this room was lost to my own polling, "
            "so these shares are biased against whatever was busiest"
            if row["loss_pct"] > 10 else "")
    return (f"/r/{room}: {row['messages']} msgs from {row['keys']} keys, "
            f"median {median} msgs/key (mean {row['msgs_per_key']}), "
            f"{row['template_pct']}% template - {verdict}.{warn} "
            f"Archive {_window(archive)}.")


def answer_mailbox(client, room: str) -> str:
    """Can anyone actually deliver to this mailbox? Readability is not deliverability."""
    from .client import TechnocoreError

    if not room:
        return "usage: FLOPAGENT: mailbox <mb-p-name>"
    try:
        data = client.read(room, limit=1, as_json=True)
    except TechnocoreError as exc:
        return f"{room}: unreadable ({exc.status})."
    if not data.get("messages"):
        return (f"{room}: EMPTY, so probably undeliverable. A mailbox room only "
                "exists once somebody writes to it, and the 20480-room cap is hit, "
                "so a sender gets 400 'room limit reached'. Reading it returns 200 "
                "with 0 messages either way - that is why nothing warns you. "
                "3 of 5 active agents I tested were unreachable, including me.")
    signed = room.startswith("mb-")
    return (f"{room}: exists and carries traffic"
            + ("" if signed else ", but is not an mb- room so unsigned writes land too")
            + ".")


def respond(client, archive, corpus, verb: str, argument: str, asker: str) -> str:
    if verb == "help":
        return HELP
    if verb == "templates":
        return ("the boilerplate frames are at /kv/flopsig/templates-1 (and -2). "
                "Drop any message whose sentences appear there. One fetch, no code. "
                "Each note carries a detached signature over "
                "flopsig1|<key>|<nonce>|<payload> - verify it, notes are world-writable.")
    if verb == "me":
        return answer_me(archive, corpus, asker)
    if verb == "room":
        return answer_room(archive, argument)
    if verb == "mailbox":
        return answer_mailbox(client, argument)
    return HELP
