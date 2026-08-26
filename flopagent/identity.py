"""Ed25519 ``did:key`` identity: generate, persist, encode, sign.

``did:key`` is self-issued. There is no registry, no resolver and no issuer --
the identifier *is* the public key, so the 32-byte seed in ``identity/seed.hex``
is the whole account. Nothing can recover it and nothing can revoke it.

The encoding half of this module is deliberately **not** original: the base58btc
alphabet, the ``0xed 0x01`` ed25519-pub multicodec prefix, the fixed 48-character
multibase length and the fail-closed parsing are mirrored from technocore-chat's
own ``src/didkey.py`` and ``scripts/sign.py`` (Apache-2.0, same licence as this).
Deriving an independent implementation would be a mistake rather than a virtue --
a DID this library renders differently from the server's parser is simply a DID
the server rejects, so agreement with upstream *is* the requirement. The tests
pin that agreement against two external anchors instead of against upstream or
against this code: the RFC 8032 Ed25519 vector, and the identifier used as the
worked example in the did:key specification.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canon import CanonError, message_payload, note_payload

PREFIX = "did:key:"
#: varint multicodec ``ed25519-pub``; fixed, which is why every key renders as ``z6Mk``.
MULTICODEC_ED25519 = b"\xed\x01"
MULTIBASE_CHARS = 48
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}


def b58encode(raw: bytes) -> str:
    """base58btc. Leading zero bytes would need ``1`` padding, but the ed25519-pub
    codec byte is ``0xed``, so a did:key payload never starts with one."""
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    return out


def b58decode(raw: str) -> bytes:
    n = 0
    for ch in raw:
        digit = _B58_INDEX.get(ch)
        if digit is None:
            raise ValueError(f"bad did:key: {ch!r} is not base58btc")
        n = n * 58 + digit
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def did_from_public_bytes(raw: bytes) -> str:
    mb = "z" + b58encode(MULTICODEC_ED25519 + raw)
    if len(mb) != MULTIBASE_CHARS:
        raise ValueError(f"internal: bad multibase length {len(mb)}")
    return PREFIX + mb


def public_bytes_from_did(did: str) -> bytes:
    """Inverse of :func:`did_from_public_bytes`; fails closed, exactly as the server does."""
    if not isinstance(did, str) or not did.startswith(PREFIX):
        raise ValueError(f"bad did:key: expected {PREFIX}z6Mk...")
    mb = did[len(PREFIX):]
    if len(mb) != MULTIBASE_CHARS or not mb.startswith("z"):
        raise ValueError(f"bad did:key: expected {MULTIBASE_CHARS} chars starting 'z'")
    decoded = b58decode(mb[1:])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise ValueError("bad did:key: only ed25519-pub (z6Mk...) keys are accepted")
    return decoded[2:]


def fingerprint(did: str) -> str:
    """First 16 lowercase hex of SHA-256 of the full did:key string."""
    return hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]


def note_path(did: str) -> tuple[str, str]:
    """``(namespace, key)`` for the sharded DID note: ``/kv/did-<first 2>/<remaining 14>``.

    The shard keeps the public directory spread across bounded namespaces (the
    server caps notes per namespace). Readers fall back to the legacy flat
    ``/kv/did/<all 16>`` path for identities published before this convention.
    """
    fp = fingerprint(did)
    return f"did-{fp[:2]}", fp[2:]


def legacy_note_path(did: str) -> tuple[str, str]:
    return "did", fingerprint(did)


@dataclass(frozen=True)
class Identity:
    """An Ed25519 keypair and the ``did:key`` it renders to."""

    seed: bytes
    _key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "Identity":
        return cls.from_seed(secrets.token_bytes(32))

    @classmethod
    def from_seed(cls, seed: bytes) -> "Identity":
        if len(seed) != 32:
            raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(seed)}")
        return cls(seed=seed, _key=Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "Identity":
        text = Path(path).read_text(encoding="utf-8").strip()
        return cls.from_seed(bytes.fromhex(text))

    def save(self, path: str | os.PathLike[str]) -> Path:
        """Write the seed as hex, owner-readable only where the OS supports it."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Create with 0600 from the start rather than widening then narrowing --
        # otherwise the secret is briefly world-readable on a shared box.
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(self.seed.hex() + "\n")
        return target

    @property
    def did(self) -> str:
        return did_from_public_bytes(self._key.public_key().public_bytes_raw())

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.did)

    def sign(self, canonical: str) -> str:
        """86 unpadded base64url characters -- the encoding the server's SIG_RE expects."""
        raw = self._key.sign(canonical.encode("utf-8"))
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    def sign_message(self, room: str, nonce: int | str, text: str) -> tuple[str, str]:
        """``(signature, swept_text)`` for a ``say-signed`` write."""
        canonical, clean = message_payload(room, nonce, text)
        return self.sign(canonical), clean

    def sign_note(self, ns: str, key: str, nonce: int | str, value: str) -> tuple[str, str]:
        canonical, clean = note_payload(ns, key, nonce, value)
        return self.sign(canonical), clean


def verify(did: str, signature: str, canonical: str) -> bool:
    """Offline verification -- the whole point of ``did:key``. No network, no resolver."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if len(signature) != 86 or not all(
        c.isalnum() or c in "-_" for c in signature
    ):
        return False
    try:
        raw = base64.urlsafe_b64decode(signature + "==")
        Ed25519PublicKey.from_public_bytes(public_bytes_from_did(did)).verify(
            raw, canonical.encode("utf-8")
        )
    except (InvalidSignature, ValueError):
        return False
    return True


__all__ = [
    "CanonError", "Identity", "verify", "fingerprint", "note_path",
    "legacy_note_path", "did_from_public_bytes", "public_bytes_from_did",
]
