"""Per-room polling cadence, so a busy room is not sampled on a quiet room's schedule.

A single sweep interval is wrong in both directions at once. Measured over twenty
minutes across ten rooms: `/r/lobby` sustains ~9 messages a second while `/r/chat`
managed two messages in the entire window. One period cannot serve both -- it
either wastes reads on the quiet room or loses history in the busy one, and a
sequential sweep makes it worse, because every wasted round-trip on a quiet room
is time the busy room keeps growing.

Losing history is not recoverable. `limit` caps at 200 and there is no `at=` or
`before=`, so once more than 200 messages land between two polls the older ones
leave the only window a reader can address -- permanently, while they still exist
on the server (FINDINGS 8). Under-polling a fast room does not delay data, it
destroys it.

So each room carries its own period, derived from its own observed rate and aimed
at collecting well under a full window each time. Rates are tracked with an
exponential moving average, because a room's pace changes and a long-run mean
would keep pacing for a burst that ended an hour ago.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

#: Aim to collect this many messages per poll. Comfortably under the server's
#: 200-message ceiling, so an ordinary burst does not immediately cost history.
TARGET_PER_POLL = 120

#: Never poll a single room faster than this, whatever its rate. The floor exists
#: to protect the read budget, not because faster is useless: /r/lobby runs at
#: ~50 messages/second, so a 5s floor asked for 250 per poll against a 200-message
#: ceiling and lost the difference every time. At 600 reads/minute per IP, polling
#: one room every 2s costs 30/min -- affordable, and the difference between
#: archiving that room and not.
MIN_PERIOD = 2.0

#: Never leave a room longer than this even when it looks dead, so a room that
#: wakes up is noticed rather than silently missed.
MAX_PERIOD = 300.0

#: Weight of the newest observation. Low enough to ignore one quiet minute,
#: high enough to follow a room that genuinely changes pace.
ALPHA = 0.3

#: How many recent rates to keep for the high-water mark. Pacing on the MEAN
#: guarantees loss during every burst, because the mean is by definition below
#: the peak and the peak is when the window overflows: /r/lobby swings between
#: ~20 and ~50 messages a second, and a period set for 20 loses a third of a
#: burst at 50. Pacing on a recent maximum trades a few extra reads on a quiet
#: room for not losing history on a busy one, which is the right trade because
#: reads are replenishable and history is not.
PEAK_WINDOW = 6


@dataclass
class RoomPace:
    """One room's observed rate and when it is next due."""

    room: str
    rate: float = 0.0          #: messages per second, EWMA -- for reporting
    due_at: float = 0.0
    #: Recent observations, so the period can be set from the peak rather than
    #: the average. This is the number the schedule actually uses.
    recent: deque = field(default_factory=lambda: deque(maxlen=PEAK_WINDOW))
    polls: int = 0
    #: Set once a poll reports loss, so the period can be cut hard rather than
    #: eased down over several observations while history keeps disappearing.
    lost_recently: bool = False

    @property
    def pace_rate(self) -> float:
        """The rate the schedule is built on: the recent peak, not the mean."""
        return max(self.recent) if self.recent else self.rate

    @property
    def period(self) -> float:
        if self.pace_rate <= 0:
            # Two different zeros. Before a second poll there is no elapsed
            # window, so no rate can be computed yet and "0" means "unmeasured" --
            # backing off the full MAX_PERIOD there stalled every room for five
            # minutes on startup and stopped the archive dead. Only a zero that
            # survived a real measurement means the room is genuinely quiet.
            return MAX_PERIOD if self.polls >= 2 else MIN_PERIOD
        wanted = TARGET_PER_POLL / self.pace_rate
        if self.lost_recently:
            # Losing means the window already overflowed. Halving is a response;
            # converging gently is just a slower way to keep losing.
            wanted /= 2
        return max(MIN_PERIOD, min(MAX_PERIOD, wanted))

    def observe(self, arrived: int, missed: int, elapsed: float, now: float) -> None:
        """Fold in one poll's result and schedule the next.

        ``arrived + missed`` is the room's real throughput: what was stored plus
        what the window had already dropped. Pacing on stored alone would read a
        saturated poll as "exactly 200 per period" and never speed up, which is
        the failure it exists to prevent.
        """
        self.polls += 1
        self.lost_recently = missed > 0
        if elapsed > 0:
            observed = (arrived + missed) / elapsed
            # Seed on the first rate we can actually compute, not the first poll.
            # A poll with no predecessor has no elapsed time, so keying on
            # `polls == 1` blended the first real measurement against zero and
            # damped it to 30% -- leaving a fast room under-polled for several
            # cycles, which is exactly when history is lost.
            self.rate = observed if self.rate == 0 else (
                ALPHA * observed + (1 - ALPHA) * self.rate
            )
            self.recent.append(observed)
        self.due_at = now + self.period


@dataclass
class Pacer:
    """Which rooms are due, and how fast each should be polled."""

    rooms: dict[str, RoomPace] = field(default_factory=dict)
    _last_poll: dict[str, float] = field(default_factory=dict)

    def track(self, room: str) -> RoomPace:
        return self.rooms.setdefault(room, RoomPace(room))

    def due(self, names: list[str], now: float | None = None) -> list[str]:
        """Rooms needing a poll, busiest first.

        Order matters on a sequential sweep: a slow room polled first is time the
        fast room spends filling up, and the fast room is the one that loses.
        """
        now = time.time() if now is None else now
        ready = [n for n in names if self.track(n).due_at <= now]
        return sorted(ready, key=lambda n: -self.rooms[n].rate)

    def observed(self, room: str, arrived: int, missed: int,
                 now: float | None = None) -> None:
        now = time.time() if now is None else now
        pace = self.track(room)
        last = self._last_poll.get(room)
        # `is not None`, not truthiness: 0.0 is a valid timestamp, and treating it
        # as "no previous poll" silently reported zero elapsed time and discarded
        # the observation. Harmless against real unix timestamps, wrong anywhere
        # else, and it made a test agree with a bug.
        pace.observe(arrived, missed, now - last if last is not None else 0.0, now)
        self._last_poll[room] = now

    def summary(self) -> str:
        live = sorted(self.rooms.values(), key=lambda p: -p.rate)[:4]
        return " ".join(f"{p.room}:{p.rate:.1f}/s@{p.period:.0f}s" for p in live)
