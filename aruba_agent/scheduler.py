"""
Simple daily task scheduler.

Registers callables at a fixed HH:MM and fires them once per calendar day.
Checks the clock every 60 s in a daemon thread.

A ±1-minute tolerance window is used when comparing the current time to the
configured schedule so that a tick delayed by system load will never silently
skip a task for the entire day.
"""

from __future__ import annotations

import logging
import threading
from datetime import date, datetime, timedelta
from typing import Callable, List, Tuple

log = logging.getLogger(__name__)

# How many minutes either side of the scheduled HH:MM are still considered "on time".
_TOLERANCE_MINUTES = 1


class Scheduler:
    def __init__(self) -> None:
        self._tasks:    List[Tuple[str, Callable]] = []
        self._last_run: dict[int, date]            = {}
        self._stop = threading.Event()

    def add(self, time_str: str, fn: Callable) -> None:
        """Register *fn* to run every day at 'HH:MM'."""
        self._tasks.append((time_str, fn))

    def _tick(self) -> None:
        now   = datetime.now()
        today = now.date()
        for time_str, fn in self._tasks:
            key = id(fn)
            if self._last_run.get(key) == today:
                continue   # already ran today
            try:
                hh, mm = map(int, time_str.split(":"))
                scheduled = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
            except (ValueError, AttributeError):
                log.warning("Scheduler: invalid time string '%s' — skipping", time_str)
                continue
            # Fire if we're within the tolerance window of the scheduled time
            if abs((now - scheduled).total_seconds()) <= _TOLERANCE_MINUTES * 60:
                self._last_run[key] = today
                name = getattr(fn, "__name__", repr(fn))
                log.info("Scheduler: firing '%s' at %s", name, time_str)
                threading.Thread(target=self._safe_run, args=(fn,), daemon=True).start()

    @staticmethod
    def _safe_run(fn: Callable) -> None:
        try:
            fn()
        except Exception as exc:
            log.error("Scheduled task '%s' raised: %s",
                      getattr(fn, "__name__", "?"), exc, exc_info=True)

    def start(self) -> None:
        def _loop() -> None:
            while not self._stop.is_set():
                self._tick()
                self._stop.wait(60)

        threading.Thread(target=_loop, name="scheduler", daemon=True).start()
        log.info("Scheduler started with %d task(s)", len(self._tasks))

    def stop(self) -> None:
        self._stop.set()

    def trigger_now(self, fn: Callable) -> None:
        """Fire *fn* immediately in a background thread (used by the web UI)."""
        threading.Thread(target=self._safe_run, args=(fn,), daemon=True).start()
