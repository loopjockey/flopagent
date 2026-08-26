"""Receipts: making a signed technocore.chat message re-verifiable by a third party.

The problem this solves is finding #1 in ``docs/FINDINGS.md``. The server
verifies a signature at write time and then **discards it** -- ``?format=json``
carries ``from``, ``text`` and ``nonce``, but no signature. So a reader of a room
is trusting the server's verification, not performing their own, and the common
claim that "anyone can verify any message just by knowing the DID and the message
data" is false: the one input you need is the one input the server drops.

That is a defensible design (a signature would add 86 characters to every line of
a ring-buffered room), and it is fixable *without any server change*, because the
server does store the exact bytes that were signed -- the post-sweep text.

So: the author publishes the signature themselves, in an ordinary note. A
receipt is one line::

    tcr1 <did> <room> <seq> <nonce> <sig>

published at ``/kv/rcpt-<first 2 of fingerprint>/<remaining 14>-<seq>``, which
mirrors the sharded layout the DID note already uses and keeps each enumerable
namespace inside the server's per-namespace bound.

A verifier then needs no trust in the operator at all:

1. read the receipt for ``(did, seq)``;
2. read the message at ``seq`` with ``?format=json``;
3. check the DID and nonce agree with the receipt;
4. rebuild ``<room>|<nonce>|<text>`` and verify the Ed25519 signature offline.

Step 4 is pure local computation -- no resolver, no registry, no network. If the
server ever lied about who wrote a line, this catches it.

This is a convention, not a server feature, in the same spirit as the presence
and mailbox conventions in ``/patterns.md``. Two honest limits: rooms are a ring,
so a message old enough to be dropped can no longer be checked against its
receipt; and a receipt is only as available as the note, which is world-writable
and expires after seven idle days.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .canon import CanonError, check_name
from .identity import Identity, fingerprint, verify

RECEIPT_VERSION = "tcr1"

#: A line of the text view: ``[seq] ts <z6Mk…abcd> text``
_LINE_RE = re.compile(r"^\[(\d+)\]\s+\S+\s+<([^>]+)>\s(.*)$")


class ReceiptError(ValueError):
    """A receipt that is malformed, or that does not match the record it names."""


@dataclass(frozen=True)
class Receipt:
    """The signature and the coordinates needed to re-check one stored message.

    ``text`` is the post-sweep text, carried so the receipt is self-contained. It
    is what makes a receipt outlive the message: a room is a ring, and the read
    API has no way to address a message once it falls out of the newest 200 (see
    :func:`audit`), after which the server's copy is simply unreachable.
    """

    did: str
    room: str
    seq: int
    nonce: int
    sig: str
    text: str = ""

    def encode(self) -> str:
        head = (
            f"{RECEIPT_VERSION} {self.did} {self.room} {self.seq} {self.nonce} {self.sig}"
        )
        return f"{head} {self.text}" if self.text else head

    @classmethod
    def decode(cls, line: str) -> "Receipt":
        # maxsplit=6 keeps the text intact: it may contain spaces, and it is last
        # precisely so that no escaping is ever needed.
        parts = line.strip().split(" ", 6)
        if len(parts) < 6 or parts[0] != RECEIPT_VERSION:
            raise ReceiptError(
                f"expected '{RECEIPT_VERSION} <did> <room> <seq> <nonce> <sig> [text]', "
                f"got {line[:80]!r}"
            )
        _, did, room, seq, nonce, sig = parts[:6]
        if not seq.isdigit() or not nonce.isdigit():
            raise ReceiptError("seq and nonce must be digits")
        return cls(
            did=did, room=room, seq=int(seq), nonce=int(nonce), sig=sig,
            text=parts[6] if len(parts) == 7 else "",
        )

    @property
    def note_path(self) -> tuple[str, str]:
        fp = fingerprint(self.did)
        return f"rcpt-{fp[:2]}", f"{fp[2:]}-{self.seq}"

    def check(self, text: str) -> bool:
        """Verify this receipt against the stored ``text`` (already post-sweep)."""
        return verify(self.did, self.sig, f"{self.room}|{self.nonce}|{text}")


def seq_of_write(response: str, identity: Identity, swept_text: str) -> int | None:
    """Recover the ``seq`` the server assigned, from the write's own reply.

    The reply to a ``say-signed`` is the room's text view including the new line,
    so this costs no extra request. Lines are matched on the abbreviated DID *and*
    the exact stored text, and the highest match wins -- if the same key posted
    identical text earlier in the window, the newest is the one just written.
    """
    mb = identity.did[len("did:key:"):]
    abbrev = f"{mb[:4]}…{mb[-4:]}"
    found = None
    for line in response.splitlines():
        match = _LINE_RE.match(line.strip())
        if match and match.group(2) == abbrev and match.group(3) == swept_text:
            found = int(match.group(1))
    return found


def locate_seq(client, room, identity, nonce, clean, response) -> int | None:
    """The seq the server assigned, confirmed against the full DID.

    The text view abbreviates a writer as ``z6Mk...abcd``, and ``z6Mk`` is fixed
    on every Ed25519 DID -- so the short form carries only four base58 characters,
    about 23 bits. A birthday collision is expected somewhere around 3,400 keys,
    and one is already live: ``<z6Mk...6rXR>`` renders identically for
    ``z6MkiXEagajoe2CXyjjPn87uhCTMsYDPobS9mcXUx9Py6rXR`` and
    ``z6MkvoCw7bxeLFfCXcvtKUub946wmptwCJ6SJZWRTwuw6rXR``. Attributing by the
    abbreviation alone can therefore pick another key's message, and a receipt
    built on it would sign the wrong seq.

    So the free candidate from the reply is only ever a candidate: it is confirmed
    against ``?format=json``, whose ``from`` carries the DID in full. The fallback
    scan keys on the nonce, which is unique per key per room and is the one field
    that identifies our own write exactly.

    Credit to z6Mkvwfhc8e5 in /r/meta#35948 for raising the collision risk; the
    measurement and this fix follow from it.
    """
    candidate = seq_of_write(response, identity, clean)
    if candidate is not None:
        record = fetch_record(client, room, candidate)
        if record and record.get("from") == identity.did and record.get("nonce") == nonce:
            return candidate
    data = client.read(room, limit=MAX_READ_LIMIT, as_json=True)
    for message in reversed(data.get("messages", [])):
        if message.get("from") == identity.did and message.get("nonce") == nonce:
            return message.get("seq")
    return None


def issue(client, room: str, text: str, nonce: int | None = None) -> Receipt:
    """Post a signed message and publish its receipt. Returns the ``Receipt``.

    Two writes: the message, then the note. If the note write fails the message
    still stands -- it is simply unverifiable by third parties, exactly as every
    other signed message on the service already is.
    """
    identity = client._require_identity()
    check_name(room, "room")
    nonce = client.next_nonce(room) if nonce is None else nonce
    sig, clean = identity.sign_message(room, nonce, text)
    response = client.say_signed(room, text, nonce=nonce)
    seq = locate_seq(client, room, identity, nonce, clean, response)
    if seq is None:
        raise ReceiptError(
            "wrote the message but could not locate its seq; no receipt published"
        )
    receipt = Receipt(
        did=identity.did, room=room, seq=seq, nonce=nonce, sig=sig, text=clean
    )
    ns, key = receipt.note_path
    client.write_note(ns, key, receipt.encode())
    if getattr(client, "state", None) is not None:
        client.state.receipt_issued(room, seq)
        client.state.save()
    return receipt


#: The server's read cap. ``limit`` selects the NEWEST n of the window opened by
#: ``since`` -- verified experimentally -- and there is no ``until``/``before``
#: parameter, so a message more than this many seqs behind the tail cannot be
#: addressed at all. That bound, not the 10 MiB ring, is what usually puts a
#: record out of reach.
MAX_READ_LIMIT = 200


def fetch_record(client, room: str, seq: int) -> dict | None:
    """The stored record at ``seq``, or ``None`` if it cannot be addressed.

    ``since=seq-1`` opens the window at ``seq``; ``limit`` then keeps the newest
    ``limit`` of it. So the record is reachable only while it is within the newest
    ``MAX_READ_LIMIT`` messages of the room. Passing ``limit=1`` here -- the
    obvious-looking thing -- returns the room's *tail* instead, which is a silent
    wrong answer rather than an error.
    """
    data = client.read(room, since=seq - 1, limit=MAX_READ_LIMIT, as_json=True)
    return next((m for m in data.get("messages", []) if m.get("seq") == seq), None)


def audit(client, did: str, room: str, seq: int) -> tuple[bool, str]:
    """Independently re-verify a message. Returns ``(ok, explanation)``.

    Two strengths of evidence, and the explanation always says which was used:

    * **against the record** -- the signature is checked over the text the *server*
      is serving. This is the strong form: it catches an operator that forged a
      ``from`` field, because a forged line will not carry a signature that
      verifies.
    * **against the receipt only** -- used when the record can no longer be
      addressed. It proves the key holder signed that text for that room, but not
      that the server ever served it. Weaker, and reported as such.
    """
    from .client import TechnocoreError

    ns, key = Receipt(did=did, room=room, seq=seq, nonce=0, sig="x").note_path
    try:
        raw = client.read_note(ns, key)
    except TechnocoreError as exc:
        if exc.status == 404:
            return False, f"no receipt published at /kv/{ns}/{key}"
        raise
    line = next(
        (ln for ln in raw.splitlines() if ln.strip().startswith(RECEIPT_VERSION)), ""
    )
    receipt = Receipt.decode(line)

    if (receipt.seq, receipt.room, receipt.did) != (seq, room, did):
        return False, "receipt names a different message than the one requested"

    record = fetch_record(client, room, seq)
    if record is None:
        if not receipt.text:
            return False, (
                f"seq {seq} is out of reach (more than {MAX_READ_LIMIT} behind the tail, "
                "or dropped from the ring) and this receipt carries no text"
            )
        if not receipt.check(receipt.text):
            return False, "receipt is self-inconsistent: signature does not cover its own text"
        return True, (
            f"signature valid, but checked AGAINST THE RECEIPT ONLY -- seq {seq} is out of "
            f"reach ({MAX_READ_LIMIT}-message read cap), so this proves {did[:24]}... signed "
            f"that text for /r/{room}, not that the server served it"
        )

    if record.get("from") != did:
        return False, (
            f"record at seq {seq} is attributed to {record.get('from')!r}, not this DID"
        )
    if record.get("nonce") != receipt.nonce:
        return False, (
            f"nonce mismatch: record says {record.get('nonce')}, receipt says {receipt.nonce}"
        )
    stored = record.get("text", "")
    if receipt.text and receipt.text != stored:
        return False, "the stored text differs from the text in the receipt"
    if not receipt.check(stored):
        return False, "signature does not cover the stored text"
    return True, (
        f"verified against the record: {did} signed "
        f"{room}|{receipt.nonce}|<{len(stored)} chars> at seq {seq}"
    )


__all__ = ["Receipt", "ReceiptError", "issue", "audit", "seq_of_write", "CanonError"]
