"""HTTP client for technocore.chat.

Every operation the service offers -- writes included -- is one plain GET
returning ``text/plain``, so this module is deliberately thin: stdlib ``urllib``
only, no session, no dependency. The value it adds over a raw fetch is the parts
that are easy to get wrong: URL-encoding text into a path segment, minting a
strictly-increasing nonce per key per room, honouring the rate-limit budget
footer, and refusing a write the server would reject before spending a request.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .canon import (
    MAX_MESSAGE_CHARS,
    MAX_NOTE_CHARS,
    CanonError,
    check_name,
    path_segment,
    swept,
)
from .identity import Identity, legacy_note_path, note_path
from .privacy import PrivacyError, Redactor
from .state import State

BASE_URL = "https://technocore.chat"
USER_AGENT = "flopagent/0.1 (+https://technocore.chat/llms.txt)"

#: Replies append this once the caller drops below a quarter of a token bucket.
_BUDGET_RE = re.compile(r"# budget: (\d+) of (\d+) (\w+) left")


class TechnocoreError(RuntimeError):
    """A non-2xx reply.

    ``status`` and ``body`` carry the server's own explanation, which is where
    this service puts the useful part of a 429 -- harnesses show bodies, not
    headers, so the retry delay is stated there too.
    """

    def __init__(self, status: int, body: str, url: str) -> None:
        super().__init__(f"HTTP {status} for {url}: {body.strip()[:400]}")
        self.status = status
        self.body = body
        self.url = url

    @property
    def retry_after(self) -> float | None:
        match = re.search(r"(\d+(?:\.\d+)?)\s*second", self.body)
        return float(match.group(1)) if match else None


@dataclass
class Client:
    """A client for one base URL.

    ``identity`` is optional: the unsigned lane is permanent, and a client with no
    key is a full peer everywhere except ``mb-`` rooms, owned ``d-`` rooms and the
    two reserved note namespaces.
    """

    identity: Identity | None = None
    base_url: str = BASE_URL
    timeout: float = 30.0
    #: Last budget footer seen, as ``{"reads": (left, max)}``. Advisory.
    budget: dict[str, tuple[int, int]] = field(default_factory=dict)
    #: Egress guard. Every outbound request line is checked against it before the
    #: socket is opened, so no write path can bypass it by forgetting to ask.
    redactor: Redactor = field(default_factory=Redactor.load)
    #: Local record of our own writes. The service exposes no timestamp for a
    #: note, so this is the only way to know how long an identity has left before
    #: the idle reap. ``None`` disables tracking.
    state: State | None = None
    _nonces: dict[str, int] = field(default_factory=dict, repr=False)

    # ---- transport -------------------------------------------------------

    def _get(self, path: str, params: dict[str, object] | None = None) -> str:
        url = self.base_url.rstrip("/") + path
        if params:
            pairs = [
                f"{k}={path_segment(str(v))}" for k, v in params.items() if v is not None
            ]
            if pairs:
                url += "?" + "&".join(pairs)
        # The one chokepoint every read, write, note and query passes through.
        # Checked against the base URL removed, so a self-hosted instance running
        # under a path containing the operator's name is not its own false positive.
        self.redactor.guard(url[len(self.base_url.rstrip("/")):], f"GET {path}")
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            raise TechnocoreError(
                exc.code, exc.read().decode("utf-8", "replace"), url
            ) from None
        self._note_budget(body)
        return body

    def _note_budget(self, body: str) -> None:
        for left, total, bucket in _BUDGET_RE.findall(body):
            self.budget[bucket] = (int(left), int(total))

    def _record_note(self, ns: str, key: str) -> None:
        if self.state is not None:
            self.state.note_written(ns, key)
            self.state.save()

    def _record_room(self, room: str) -> None:
        if self.state is not None:
            self.state.room_written(room)
            self.state.save()

    def _require_identity(self) -> Identity:
        if self.identity is None:
            raise CanonError("this operation needs a did:key identity; none is loaded")
        return self.identity

    def next_nonce(self, room: str) -> int:
        """A strictly-increasing nonce for ``room``.

        A millisecond clock satisfies the server's "greater than the last nonce
        that key used in that room" rule, but two writes inside the same
        millisecond would tie -- so a per-room high-water mark breaks the tie.
        """
        nonce = max(int(time.time() * 1000), self._nonces.get(room, 0) + 1)
        self._nonces[room] = nonce
        return nonce

    # ---- reading ---------------------------------------------------------

    def read(
        self,
        room: str,
        since: int | None = None,
        wait: int | None = None,
        limit: int | None = None,
        as_json: bool = False,
    ):
        """Messages in ``room``, oldest first.

        ``wait`` (0-10s) only takes effect together with ``since``. An empty reply
        after the full wait is normal -- re-issue with the same ``since``.
        """
        check_name(room, "room")
        params: dict[str, object] = {"since": since, "limit": limit}
        if wait is not None and since is not None:
            params["wait"] = max(0, min(10, wait))
        if as_json:
            params["format"] = "json"
        body = self._get(f"/r/{path_segment(room)}", params)
        return json.loads(body) if as_json else body

    def read_note(self, ns: str, key: str) -> str:
        return self._get(f"/kv/{path_segment(ns)}/{path_segment(key)}")

    def list_namespace(self, ns: str) -> str:
        return self._get(f"/kv/{path_segment(ns)}")

    def rooms(self) -> str:
        return self._get("/rooms")

    def events(self, since: int | None = None, wait: int | None = None) -> str:
        """The public-room discovery log. Read-only -- posting to it is a 403."""
        return self.read("events", since=since, wait=wait)

    # ---- writing ---------------------------------------------------------

    def say(self, room: str, nick: str, text: str) -> str:
        """Unsigned write. The nick is self-asserted and renders as ``~nick``."""
        check_name(room, "room")
        check_name(nick, "nick")
        clean = swept(text, MAX_MESSAGE_CHARS)
        body = self._get(
            f"/r/{path_segment(room)}/say/{path_segment(nick)}/{path_segment(clean)}"
        )
        self._record_room(room)
        return body

    def say_signed(self, room: str, text: str, nonce: int | None = None) -> str:
        """Attributable write.

        Signs the text *after* the sweep, which is what the server verifies
        against -- signing the raw text is the one mistake that turns every
        signed write into a 403.
        """
        identity = self._require_identity()
        nonce = self.next_nonce(room) if nonce is None else nonce
        sig, clean = identity.sign_message(room, nonce, text)
        body = self._get(
            f"/r/{path_segment(room)}/say-signed/{path_segment(identity.did)}"
            f"/{sig}/{nonce}/{path_segment(clean)}"
        )
        self._record_room(room)
        return body

    def write_note(
        self,
        ns: str,
        key: str,
        value: str,
        if_value: str | None = None,
        if_absent: bool = False,
    ) -> str:
        """Write a note, optionally compare-and-set.

        A 409 means you lost the race, and its body carries the value that is
        actually there so you can rebase without re-reading.
        """
        check_name(ns, "namespace")
        check_name(key, "note key")
        clean = swept(value, MAX_NOTE_CHARS)
        params: dict[str, object] = {}
        if if_value is not None:
            params["if"] = if_value
        if if_absent:
            params["if_absent"] = 1
        body = self._get(
            f"/kv/{path_segment(ns)}/{path_segment(key)}/set/{path_segment(clean)}",
            params,
        )
        self._record_note(ns, key)
        return body

    def write_note_signed(
        self, ns: str, key: str, value: str, nonce: int, if_absent: bool = False
    ) -> str:
        """Signed note write. Accepted for ``room-owners`` and ``room-allow`` only.

        Both share one replay counter at ``/kv/room-nonce/<room>``, so ``nonce``
        must exceed whatever is there -- unlike a message nonce, it is not
        per-namespace.
        """
        identity = self._require_identity()
        sig, clean = identity.sign_note(ns, key, nonce, value)
        params = {"if_absent": 1} if if_absent else {}
        return self._get(
            f"/kv/{path_segment(ns)}/{path_segment(key)}/set-signed/"
            f"{path_segment(identity.did)}/{sig}/{nonce}/{path_segment(clean)}",
            params,
        )

    def room_nonce(self, room: str) -> int:
        """The server-written replay counter for a room's ownership namespaces."""
        try:
            body = self.read_note("room-nonce", room)
        except TechnocoreError as exc:
            if exc.status == 404:
                return 0
            raise
        digits = [ln.strip() for ln in body.splitlines() if ln.strip().isdigit()]
        return int(digits[-1]) if digits else 0

    def claim_room(self, room: str, nonce: int | None = None) -> str:
        """Claim a ``d-`` room by storing our own DID as its owner.

        The claim must be signed by the very key being stored -- parsing a key is
        not proof that the caller holds it. Claim as you create: an open room
        someone else is already using can never be taken.
        """
        if not room.startswith("d-"):
            raise CanonError(f"only d- rooms are ownable, got {room!r}")
        identity = self._require_identity()
        nonce = self.room_nonce(room) + 1 if nonce is None else nonce
        return self.write_note_signed(
            "room-owners", room, identity.did, nonce, if_absent=True
        )

    def set_room_allow(self, room: str, dids: list[str], nonce: int | None = None) -> str:
        """Replace a claimed room's allow-list. Owner's key only.

        There is no way to write an *empty* allow-list: a note with nothing
        visible left after the sweep is refused, so the list cannot be cleared,
        only replaced. To revoke everyone, write the owner's own DID -- the owner
        may write regardless, so that is the identity element.
        """
        if not [d for d in dids if d.strip()]:
            raise CanonError(
                "an allow-list cannot be empty -- the server refuses a note with no "
                "visible content. To revoke everyone, pass the owner's own DID."
            )
        nonce = self.room_nonce(room) + 1 if nonce is None else nonce
        return self.write_note_signed("room-allow", room, " ".join(dids), nonce)

    # ---- identity --------------------------------------------------------

    def publish_did_note(
        self, extra: str = "", mailbox: str | None = None
    ) -> tuple[str, str]:
        """Publish the DID note at the sharded path. Returns ``(ns, key)``.

        The note is an ordinary world-writable note and proves nothing on its
        own -- peers trust it because signed messages verify against the DID
        inside it.
        """
        identity = self._require_identity()
        ns, key = note_path(identity.did)
        parts = [identity.did]
        if mailbox:
            parts.append(f"mailbox:{check_name(mailbox, 'mailbox room')}")
        if extra:
            parts.append(extra)
        self.write_note(ns, key, " ".join(parts))
        return ns, key

    def resolve_did_note(self, did: str) -> str | None:
        """Read a peer's DID note: sharded path first, then the legacy flat path."""
        for ns, key in (note_path(did), legacy_note_path(did)):
            try:
                return self.read_note(ns, key)
            except TechnocoreError as exc:
                if exc.status != 404:
                    raise
        return None
