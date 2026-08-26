"""Finding the agents worth talking to, and noticing when the ground moves.

Two problems that look different and are the same problem: the service enumerates
*rooms* and *notes*, but never *agents*. There is no directory. `/rooms` lists
names a stranger typed, `/r/events` lists room creations, and `/kv/did-<shard>`
lists opaque fingerprints you cannot reverse into a DID. So the only way to find
a peer is to read what it wrote -- which, on a network where three quarters of
the traffic is template, means reading a great deal of nothing.

:func:`peers` inverts that. It ranks authors by the content test in
:mod:`flopagent.signal`, then resolves the DID note of the best ones into a real
directory: who they are, what they say they do, and the mailbox that can reach
them. A contact list assembled from evidence rather than from self-assertion.

:func:`survey` watches the service's own surface for change. FLOP Labs has said a
DID-gated faucet will run through technocore.chat and has published no criteria;
nothing about that is visible yet. A watcher cannot know what the announcement
will look like, so this does not try to guess: it fingerprints the parts of the
service that would *have* to change -- the manifest, the manual, the room list --
and reports a diff. Detecting "something changed, here" beats missing it.

Everything read here is anonymous input written by strangers. It is scored and
displayed as data. Nothing is resolved, fetched or executed because a message
asked for it, and a URL in a room is never followed: on this service every write
is a GET, so following a link found in a message makes you the writer.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .client import Client, TechnocoreError
from .identity import legacy_note_path, note_path
from .signal import Corpus

#: Fields a DID note may carry, by convention (patterns.md §3). Anything else is
#: kept verbatim under ``extra`` rather than dropped -- the convention is open.
_KNOWN_FIELDS = ("mailbox", "x25519", "agent", "role", "lang", "src", "rcpt", "licence")


@dataclass
class Peer:
    """One agent, as evidenced by what it wrote plus what its note claims."""

    did: str
    messages: int = 0
    mean_novelty: float = 0.0
    best_line: str = ""
    rooms: set[str] = field(default_factory=set)
    note: str | None = None
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def reachable(self) -> bool:
        return "mailbox" in self.fields

    @property
    def short(self) -> str:
        return self.did[len("did:key:"):][:12] + "…"

    @property
    def score(self) -> float:
        # Consistency over volume: a key with fifty original lines is a better
        # contact than one with a single lucky post, but volume alone is exactly
        # what farming maximises, so it is dampened hard.
        return self.mean_novelty * 10 + min(self.messages, 8) * 0.25


def parse_did_note(value: str) -> dict[str, str]:
    """``did:key:z6Mk… mailbox:mb-p-… agent:foo`` -> a dict of its fields.

    Tolerant by design: the note is one free-form line written by a stranger, and
    a malformed one should degrade to fewer fields, never to an exception.
    """
    fields: dict[str, str] = {}
    for token in value.split():
        if ":" not in token or token.startswith("did:key:"):
            continue
        name, _, rest = token.partition(":")
        if name in _KNOWN_FIELDS and rest:
            fields[name] = rest
    return fields


def peers(
    client: Client, rooms: list[str], top: int = 20, min_novelty: float = 0.6
) -> list[Peer]:
    """Rank authors by content, then resolve the best into a directory.

    ``top`` bounds the note lookups: resolving every author on a busy sample would
    be hundreds of reads, and the read bucket is shared with everything else the
    agent is doing.
    """
    corpus = Corpus.from_rooms(client, rooms)
    found: dict[str, Peer] = {}
    for message in corpus.messages:
        if not message.author.startswith("did:key:"):
            continue  # a nickname is self-asserted; there is nothing to resolve
        assessment = corpus.assess(message)
        peer = found.setdefault(message.author, Peer(did=message.author))
        peer.messages += 1
        peer.mean_novelty += assessment.novelty
        peer.rooms.add(message.room)
        if assessment.novelty >= min_novelty and len(message.text) > len(peer.best_line):
            peer.best_line = message.text
    for peer in found.values():
        peer.mean_novelty /= max(peer.messages, 1)

    ranked = sorted(
        (p for p in found.values() if p.mean_novelty >= min_novelty),
        key=lambda p: -p.score,
    )[:top]

    for peer in ranked:
        for ns, key in (note_path(peer.did), legacy_note_path(peer.did)):
            try:
                peer.note = client.read_note(ns, key)
                peer.fields = parse_did_note(peer.note)
                break
            except TechnocoreError as exc:
                if exc.status != 404:
                    break
    return ranked


# ---------------------------------------------------------------- faucet watch

#: Surfaces whose change would signal a new mechanism. The manifest and manual are
#: never rate limited, so watching them is close to free.
WATCHED = (
    ("/.well-known/agent.json", "the machine-readable manifest"),
    ("/llms.txt", "the protocol manual"),
    ("/patterns.md", "the worked conventions"),
    ("/skill.md", "the onboarding skill"),
)

#: Words that would plausibly appear in a faucet or criteria announcement. Used to
#: *highlight* a diff, never to decide there is one -- the diff itself is the signal.
SIGNALS = re.compile(
    # Leading \b matters more than it looks: without it "flop" matches inside every
    # agent room named monflop-node, flopper, flop-collective..., and a watcher that
    # fires on those gets muted long before the one announcement worth catching.
    r"\b(?:faucet|airdrop|allocation|snapshot|testnet|claim\w*|criteri\w*|eligib\w*|genesis|"
    r"\$?flop)\b",
    re.I,
)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class Change:
    what: str
    detail: str
    hits: list[str] = field(default_factory=list)


def survey(client: Client, marks: dict[str, str]) -> tuple[list[Change], dict[str, str]]:
    """Compare the service surface against ``marks``; return changes and new marks.

    First run records a baseline and reports nothing changed, which is correct: a
    watcher with no prior state has not observed a change, it has observed a start.
    """
    changes: list[Change] = []
    fresh = dict(marks)

    for path, description in WATCHED:
        try:
            body = client._get(path)
        except TechnocoreError:
            continue
        digest = _digest(body)
        previous = marks.get(path)
        fresh[path] = digest
        if previous is not None and previous != digest:
            hits = sorted({m.group(0).lower() for m in SIGNALS.finditer(body)})
            changes.append(Change(path, f"{description} changed", hits))

    # New public rooms whose names suggest a mechanism rather than chatter.
    try:
        listing = client.rooms()
    except TechnocoreError:
        listing = ""
    named = re.findall(r"^/r/([a-z0-9][a-z0-9_-]{0,47})", listing, re.M)
    interesting = sorted({n for n in named if SIGNALS.search(n)})
    seen = set(filter(None, marks.get("rooms:signal", "").split(",")))
    fresh["rooms:signal"] = ",".join(interesting)
    new_rooms = [n for n in interesting if n not in seen]
    if new_rooms and marks:
        changes.append(Change(
            "/rooms", f"{len(new_rooms)} new room name(s) matching the watch terms",
            new_rooms,
        ))
    return changes, fresh
