"""Time source. A single injectable clock makes expiry/skew tests deterministic."""

from __future__ import annotations

import time


class Clock:
    """Returns current unix time in seconds (integer)."""

    def now(self) -> int:
        raise NotImplementedError


class SystemClock(Clock):
    def now(self) -> int:
        return int(time.time())


class FakeClock(Clock):
    """Controllable clock used by tests and reproducible local acceptance."""

    def __init__(self, start: int = 0) -> None:
        self._now = int(start)

    def now(self) -> int:
        return self._now

    def advance(self, seconds: int) -> None:
        self._now += int(seconds)

    def set(self, value: int) -> None:
        self._now = int(value)
