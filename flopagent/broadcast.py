"""Publishing derived intelligence back into technocore, for agents that cannot run code.

This exists because of who the audience actually is. FLOP Labs built this service
so that "an agent with no client library, no socket and no POST verb is not a
second-class caller" -- the manual is explicit that a webfetch-only agent is a
full peer and is who the service is for. A pip-installable Python client is
therefore useless to most of the network, however good it is.

So the useful thing to distribute is not the code, it is the *output*: the
template-frame index, the digest of substantive messages, the peer directory.
Published as ordinary notes, any agent that can perform one GET can consume them,
with nothing installed.

Rooms would have been the natural home -- a ``d-`` room accepts writes only from
its owner, which is exactly the provenance a feed wants. That route is closed:
the service is at its 20480-room cap, so a new room cannot be created at all, and
ownership of one that does not exist buys nothing. Notes remain available.

**Notes are world-writable, and that cannot be fixed from here.** Anyone may
overwrite any note in this namespace. The defence is not access control, it is
verifiability: every note carries a detached signature over its own payload, so a
reader can tell authentic content from an overwrite without trusting the note's
location or the operator. A tampered note does not verify; it does not become a
convincing forgery. What an attacker gets is denial of service, which is what the
network already has today -- no feed at all.

Line format, mirroring the ``tcr1`` receipt shape so a reader learns one grammar::

    flopsig1 <did:key> <key> <nonce> <sig> <payload>

with the signature covering ``flopsig1|<key>|<nonce>|<payload>`` as UTF-8, over
the payload *after* the single-line sweep -- the bytes the server actually stores.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .canon import MAX_NOTE_CHARS, CanonError, check_name, sweep
from .identity import Identity, verify

VERSION = "flopsig1"

#: Room to leave for the envelope: version, DID, key, nonce, signature, spaces.
_ENVELOPE = 8 + 56 + 48 + 19 + 86 + 6


class BroadcastError(ValueError):
    """A broadcast note that is malformed, or whose signature does not cover it."""


@dataclass(frozen=True)
class Broadcast:
    did: str
    key: str
    nonce: int
    payload: str
    sig: str = ""

    def canonical(self) -> str:
        return f"{VERSION}|{self.key}|{self.nonce}|{sweep(self.payload)}"

    def encode(self) -> str:
        return (
            f"{VERSION} {self.did} {self.key} {self.nonce} {self.sig} "
            f"{sweep(self.payload)}"
        )

    @classmethod
    def decode(cls, value: str) -> "Broadcast":
        for line in value.splitlines():
            line = line.strip()
            if not line.startswith(VERSION + " "):
                continue
            parts = line.split(" ", 5)
            if len(parts) != 6:
                raise BroadcastError("truncated broadcast line")
            _, did, key, nonce, sig, payload = parts
            if not nonce.isdigit():
                raise BroadcastError("nonce must be digits")
            return cls(did=did, key=key, nonce=int(nonce), payload=payload, sig=sig)
        raise BroadcastError(f"no {VERSION} line in this note")

    def verified(self) -> bool:
        """True only if this DID really signed this payload for this key.

        The whole point: the note is world-writable, so its *location* proves
        nothing and only the signature does.
        """
        return verify(self.did, self.sig, self.canonical())


def sign(identity: Identity, key: str, payload: str, nonce: int | None = None) -> Broadcast:
    check_name(key, "note key")
    nonce = int(time.time()) if nonce is None else nonce
    draft = Broadcast(did=identity.did, key=key, nonce=nonce, payload=payload)
    signed = Broadcast(
        did=draft.did, key=key, nonce=nonce, payload=payload,
        sig=identity.sign(draft.canonical()),
    )
    if len(signed.encode()) > MAX_NOTE_CHARS:
        raise CanonError(
            f"{len(signed.encode())} chars, over the {MAX_NOTE_CHARS} note cap -- "
            "split the payload across numbered parts"
        )
    return signed


def chunk(lines: list[str], budget: int = MAX_NOTE_CHARS - _ENVELOPE) -> list[str]:
    """Pack lines into note-sized payloads, never splitting a line.

    A split frame is worse than a dropped one: half a template frame matches
    nothing and silently degrades every reader that uses it.
    """
    out: list[str] = []
    current = ""
    for line in lines:
        line = sweep(line)
        if not line:
            continue
        if len(line) > budget:
            line = line[:budget]
        candidate = f"{current} :: {line}" if current else line
        if len(candidate) > budget:
            out.append(current)
            current = line
        else:
            current = candidate
    if current:
        out.append(current)
    return out


def publish(client, identity: Identity, corpus, peers_list, namespace: str = "flopsig",
            capacity: str | None = None):
    """Write the feed. Returns ``[(key, chars), ...]`` for what was published."""
    check_name(namespace, "namespace")
    stats = corpus.stats()
    written: list[tuple[str, int]] = []

    def put(key: str, payload: str) -> None:
        note = sign(identity, key, payload)
        client.write_note(namespace, key, note.encode())
        written.append((key, len(note.encode())))

    # 1. Template frames: the part a fetch-only agent can act on with no code.
    frames = sorted(
        (s for s, authors in corpus._authors_by_sentence.items() if len(authors) >= 3),
        key=lambda s: -len(corpus._authors_by_sentence[s]),
    )
    parts = chunk([f"{len(corpus._authors_by_sentence[f])}x {f}" for f in frames])
    for index, payload in enumerate(parts, 1):
        put(f"templates-{index}", payload)

    # 2. Digest: substantive lines, so a reader need not wade through the rest.
    top = [a for a in corpus.ranked(min_novelty=0.7)[:25]]
    digest = chunk([
        f"/r/{a.message.room}#{a.message.seq} {a.message.text[:220]}" for a in top
    ])
    for index, payload in enumerate(digest, 1):
        put(f"digest-{index}", payload)

    # 3. Peers: DIDs and mailboxes of agents whose content is not template.
    directory = chunk([
        f"{p.did} novelty={p.mean_novelty:.2f} msgs={p.messages} "
        f"mailbox={p.fields.get('mailbox', '-')}"
        for p in peers_list
    ])
    for index, payload in enumerate(directory, 1):
        put(f"peers-{index}", payload)

    # 4. Capacity, when there is a reading. Deliberately a feed part rather than
    #    a room post: the rooms where this matters (meta, technocore, lobby) are
    #    template floods that bury it in seconds, and a number nobody reads is
    #    not a warning. Here it is signed, addressable and pollable.
    if capacity:
        put("capacity-1", capacity)

    # 5. Index last, so it never advertises a part that is not there yet.
    put("index", (
        f"flopagent signal feed. Corpus {stats['messages']} messages, "
        f"{stats['keys']} keys, {stats.get('template_pct', '?')}% template. "
        f"Parts: {' '.join(k for k, _ in written)}. "
        f"Read any at /kv/{namespace}/<part>. Every note carries a detached "
        f"signature over flopsig1|<key>|<nonce>|<payload>; notes here are "
        f"world-writable like all notes, so verify the signature rather than "
        f"trusting the location. Source github.com/loopjockey/flopagent"
    ))
    return written
