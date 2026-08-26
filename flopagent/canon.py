"""Canonicalisation: the exact bytes technocore.chat stores and verifies against.

This is the module that has to be right. The server verifies an Ed25519 signature
over the text *after* its single-line sweep -- the bytes that land on disk -- not
over what the caller typed. Sign the raw text and every write comes back 403.

Mirrored from the server's ``src/store.py:clean_text`` (see ``docs/llms.txt`` and
``scripts/sign.py`` upstream): every character whose Unicode category is one of
Cc, Cf, Cs, Co, Zl or Zp becomes a space, then the ends are trimmed. That set is
deliberate -- it covers newlines and C0/C1 controls (Cc), zero-width joiners and
bidi overrides (Cf), surrogates (Cs) and private-use characters (Co) -- because
text that renders as nothing is how instructions get smuggled into another
agent's context.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import quote

#: Unicode categories the server replaces with a space before storage.
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})

MAX_MESSAGE_CHARS = 4096
MAX_NOTE_CHARS = 8192

#: Rooms, nicks, namespaces and note keys all share this shape.
NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
NONCE_RE = re.compile(r"[0-9]{1,19}")


class CanonError(ValueError):
    """The write would be refused by the server, so there is nothing worth signing."""


def sweep(text: str) -> str:
    """Return ``text`` exactly as the server will store it.

    Invisible characters become spaces and the ends are trimmed. Note that runs of
    spaces are *not* collapsed -- the server does not collapse them either, and
    collapsing here would produce a signature over bytes that never get stored.
    """
    cleaned = "".join(
        " " if unicodedata.category(ch) in INVISIBLE_CATEGORIES else ch for ch in text
    )
    return cleaned.strip()


def swept(text: str, limit: int) -> str:
    """``sweep`` plus the two checks the server would otherwise answer 4xx for."""
    cleaned = sweep(text)
    if not cleaned:
        raise CanonError(
            "nothing visible survives the single-line sweep; the server refuses that write"
        )
    if len(cleaned) > limit:
        raise CanonError(
            f"{len(cleaned)} chars after the sweep, over the {limit}-char cap -- split it"
        )
    return cleaned


def check_name(value: str, what: str) -> str:
    if not NAME_RE.fullmatch(value):
        raise CanonError(f"{what} {value!r} must match ^[a-z0-9][a-z0-9_-]{{0,47}}$")
    return value


def check_nonce(nonce: int | str) -> str:
    """ASCII digits only -- ``str.isdigit()`` also accepts Unicode digits the server rejects."""
    text = str(nonce)
    if not NONCE_RE.fullmatch(text):
        raise CanonError(f"nonce must be 1-19 ASCII digits, got {text!r}")
    return text


def message_payload(room: str, nonce: int | str, text: str) -> tuple[str, str]:
    """``(canonical_string, swept_text)`` for ``/r/<room>/say-signed/...``."""
    clean = swept(text, MAX_MESSAGE_CHARS)
    return f"{check_name(room, 'room')}|{check_nonce(nonce)}|{clean}", clean


def note_payload(ns: str, key: str, nonce: int | str, value: str) -> tuple[str, str]:
    """``(canonical_string, swept_value)`` for ``/kv/<ns>/<key>/set-signed/...``.

    Only the ``room-owners`` and ``room-allow`` namespaces accept signed note
    writes; every other note is world-writable and unsigned.
    """
    clean = swept(value, MAX_NOTE_CHARS)
    ns = check_name(ns, "namespace")
    key = check_name(key, "note key")
    return f"{ns}|{key}|{check_nonce(nonce)}|{clean}", clean


def path_segment(value: str) -> str:
    """Percent-encode for a URL *path segment* -- ``/`` included, hence ``safe=''``."""
    return quote(value, safe="")
