"""
Tests for aruba_agent.scheduler — specifically the ±1-minute tolerance
window we added so a scheduler tick delayed by GC / GIL pressure
doesn't silently skip a daily task.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import patch

from aruba_agent.scheduler import Scheduler


def _scheduler_with_task():
    """Return (scheduler, task_callable, task_id) for fixtures below."""
    sched = Scheduler()
    calls = []
    def t() -> None:
        calls.append(True)
    sched.add("02:00", t)
    return sched, t, calls


def _tick_at(sched: Scheduler, when: datetime, calls: list) -> bool:
    """
    Tick the scheduler with the clock pinned to ``when`` and report
    whether the task fired. We swap in a synchronous _safe_run so we
    don't have to deal with threading inside the test.
    """
    fired_before = len(calls)
    with patch("aruba_agent.scheduler.datetime") as dt:
        dt.now.return_value = when
        # Pass the real types through to the rest of the module so
        # `now.replace(...)` and date arithmetic still work.
        dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
        # Run scheduled tasks synchronously by stubbing Thread.start.
        with patch("aruba_agent.scheduler.threading.Thread") as thr:
            instances = []
            def factory(target=None, args=(), daemon=None, name=None, **kw):
                # Run inline so the test sees the side effect immediately.
                target(*args)
                class _Inst:
                    def start(self_): pass
                instances.append(_Inst())
                return instances[-1]
            thr.side_effect = factory
            sched._tick()
    return len(calls) > fired_before


def test_fires_on_exact_minute():
    sched, _t, calls = _scheduler_with_task()
    assert _tick_at(sched, datetime(2026, 5, 12, 2, 0, 0), calls)


def test_fires_within_one_minute_late():
    sched, _t, calls = _scheduler_with_task()
    # 60 seconds past the scheduled time — still inside the window.
    assert _tick_at(sched, datetime(2026, 5, 12, 2, 0, 59), calls)


def test_does_not_fire_when_too_late():
    sched, _t, calls = _scheduler_with_task()
    # 90 seconds past — outside the ±1-minute tolerance.
    assert not _tick_at(sched, datetime(2026, 5, 12, 2, 1, 30), calls)


def test_does_not_fire_before_schedule():
    sched, _t, calls = _scheduler_with_task()
    # 90 seconds early — outside the window too.
    assert not _tick_at(sched, datetime(2026, 5, 12, 1, 58, 30), calls)


def test_does_not_double_fire_same_day():
    sched, _t, calls = _scheduler_with_task()
    assert _tick_at(sched, datetime(2026, 5, 12, 2, 0, 0), calls)
    assert not _tick_at(sched, datetime(2026, 5, 12, 2, 0, 30), calls)
    assert len(calls) == 1


def test_fires_again_next_day():
    sched, _t, calls = _scheduler_with_task()
    assert _tick_at(sched, datetime(2026, 5, 12, 2, 0, 0), calls)
    # Next calendar day, same time.
    assert _tick_at(sched, datetime(2026, 5, 13, 2, 0, 0), calls)
    assert len(calls) == 2


def test_invalid_time_string_is_skipped_not_raised():
    sched = Scheduler()
    called = []
    sched.add("not-a-time", lambda: called.append(True))
    sched.add("03:00",      lambda: called.append("3am"))

    with patch("aruba_agent.scheduler.datetime") as dt:
        dt.now.return_value = datetime(2026, 5, 12, 3, 0, 0)
        dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
        with patch("aruba_agent.scheduler.threading.Thread") as thr:
            def factory(target=None, args=(), **kw):
                target(*args)
                class _I:
                    def start(self): pass
                return _I()
            thr.side_effect = factory
            sched._tick()
    assert called == ["3am"]
