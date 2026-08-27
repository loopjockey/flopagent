"""Acquiring a mailbox on a service whose room table is full.

A DID note may advertise a `mailbox:` field, and the onboarding instructions say
to publish one: `flopagent publish --mailbox mb-p-<random>`. On this service that
instruction cannot be followed. A room only comes into existence when somebody
writes to it, the room table is at its cap, and a write that would create a new
room is refused:

    400 room limit reached (20480 is the cap, and this would be a new one).
    Existing rooms still accept writes, so reuse one you already have.

So the advertised address is one nobody can deliver to -- which is worse than
advertising nothing, because a sender reads the note, writes, and gets a 400 that
looks like *their* fault. Health checking already refuses to advertise an address
in that state; this module is the other half, the part that gets one.

The cap is not a wall, it is a queue. The same error names the eviction rule: an
idle room is reclaimed after 7 days, and a room still on its first message after
24 hours. Slots free continuously. A single claim attempt is therefore not a
failure to be reported, it is one poll of a retry loop that should keep running.

Two consequences shape what is here:

* **The address must be stable across attempts.** Generating a new name per try
  would mean the address finally claimed is not the one anything else recorded.
  The pending name is written down before the first attempt and reused after.
* **Winning the slot is not keeping it.** A freshly created room is still on its
  first message, so it is on the 24-hour clock, not the 7-day one -- and it stays
  there until somebody else writes. A mailbox that goes quiet is reclaimed and
  the address goes dead again, silently. Holding it costs one write per beacon
  period, which is the cheapest of the available options and the only one that
  does not depend on a stranger arriving in time.
"""

from __future__ import annotations

import secrets
import time
from pathlib import Path

from .client import TechnocoreError

#: The server's own words when a write would create a room and cannot.
CAP_PHRASE = "room limit reached"

#: A room still on its first message is reclaimed after 24 hours. Beacon well
#: inside that, so a missed pass or a throttled daemon does not lose the room.
BEACON_EVERY = 6 * 3600

_GREETING = "FLOPAGENT mailbox open. Send: FLOPAGENT help"
_BEACON = "FLOPAGENT mailbox held. Send: FLOPAGENT help"


class MailboxClaimer:
    """Poll for a free room slot, then hold the room that was won.

    State lives in three files beside the seed, because the daemon that uses this
    is restarted often and an address remembered only in memory is an address
    abandoned at every restart:

    ``mailbox.txt``             the held address; the daemon publishes this one
    ``mailbox.pending.txt``     the address being retried, before it is won
    ``mailbox.beacon``          when the held room was last written to
    """

    def __init__(self, directory: Path | str, now=time.time,
                 beacon_every: float = BEACON_EVERY) -> None:
        self.dir = Path(directory)
        self.now = now
        self.beacon_every = beacon_every

    # ---- recorded state --------------------------------------------------

    @property
    def held(self) -> str | None:
        """The address that exists and is ours, or None while still queueing."""
        path = self.dir / "mailbox.txt"
        return path.read_text().strip() if path.exists() else None

    @property
    def pending(self) -> str:
        """The address to keep trying for -- decided once, then reused.

        An address abandoned by an earlier attempt (`mailbox.unreachable.txt`, as
        left by the health check that found it undeliverable) is preferred over a
        fresh one. It is not tainted: it was never created, so nothing is stored
        against it, and reusing it keeps a single address in the record instead of
        a trail of ones that were tried once.
        """
        path = self.dir / "mailbox.pending.txt"
        if path.exists():
            return path.read_text().strip()
        abandoned = self.dir / "mailbox.unreachable.txt"
        name = (abandoned.read_text().strip() if abandoned.exists()
                else f"mb-p-{secrets.token_hex(10)}")
        self.dir.mkdir(parents=True, exist_ok=True)
        path.write_text(name + "\n")
        return name

    @property
    def advertised(self) -> str | None:
        """The address last written into the DID note, as far as we know.

        Kept separately from `held` because the two really can differ: the room
        is created by a write to this service, the address is announced in a note
        on another namespace, and a restart between the two leaves a mailbox that
        exists and that nobody has been told about.
        """
        path = self.dir / "mailbox.advertised.txt"
        return path.read_text().strip() if path.exists() else None

    @advertised.setter
    def advertised(self, address: str) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "mailbox.advertised.txt").write_text(address + "\n")

    # ---- the poll --------------------------------------------------------

    def attempt(self, client) -> str:
        """One poll: hold what we have, or try once more to get it.

        Never raises for the two outcomes that are ordinary -- a full service and
        a throttled one are both "not this time". Anything else is reported in the
        status rather than swallowed, because a mailbox that silently never
        arrives is the failure this module exists to end.
        """
        address = self.held
        if address:
            return self._hold(client, address)
        return self._claim(client)

    def _claim(self, client) -> str:
        wanted = self.pending
        try:
            client.say_signed(wanted, _GREETING)
        except TechnocoreError as exc:
            if exc.status == 400 and CAP_PHRASE in exc.body:
                return f"cap full, still queueing for {wanted}"
            return f"claim failed: HTTP {exc.status}"
        (self.dir / "mailbox.txt").write_text(wanted + "\n")
        self._stamp()
        return f"claimed {wanted}"

    def _hold(self, client, address: str) -> str:
        if self.now() - self._stamped() < self.beacon_every:
            return f"held {address}"
        try:
            client.say_signed(address, _BEACON)
        except TechnocoreError as exc:
            return f"beacon failed: HTTP {exc.status}"
        self._stamp()
        return f"beacon sent to {address}"

    # ---- beacon clock ----------------------------------------------------

    def _stamp(self) -> None:
        (self.dir / "mailbox.beacon").write_text(f"{self.now():.0f}\n")

    def _stamped(self) -> float:
        path = self.dir / "mailbox.beacon"
        if not path.exists():
            return 0.0
        try:
            return float(path.read_text().strip())
        except ValueError:
            return 0.0
