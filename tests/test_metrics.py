"""
Tests for aruba_agent.metrics — the /metrics renderer used by
Prometheus. Most of the value here is the safe-when-missing path:
the agent must keep booting cleanly even on a host that hasn't
installed prometheus-client yet.
"""

from __future__ import annotations

import pytest

from aruba_agent import metrics


@pytest.fixture(autouse=True)
def _reset_counters():
    """Each test starts with zeroed process counters."""
    snap = metrics._snapshot_counters()
    yield
    # Reset by rewriting back to zero for all known counters.
    for k in snap:
        # type: ignore[attr-defined]
        metrics._counters[k] = 0


def test_inc_increments_known_counter():
    metrics.inc("login_failures_total")
    assert metrics._snapshot_counters()["login_failures_total"] == 1


def test_inc_by_n_works():
    metrics.inc("login_failures_total", 5)
    assert metrics._snapshot_counters()["login_failures_total"] == 5


def test_inc_unknown_counter_is_silent():
    """An unknown name should be dropped rather than crash the hot
    login path. Tighter contracts would risk shipping a typo that
    blocks production logins."""
    metrics.inc("totally-not-a-real-metric")
    snap = metrics._snapshot_counters()
    # The known counters are unchanged.
    for v in snap.values():
        assert v == 0


def test_render_returns_valid_content_type():
    class FakeState:
        def to_dict(self):
            return {"switches": [], "backup": {}, "scanner": {},
                    "arp_last_run": {}}
    body, ct = metrics.render(FakeState())
    # Prometheus text format 0.0.4 has a specific content-type signature
    assert "text/plain" in ct
    assert isinstance(body, (bytes, bytearray))


def test_render_does_not_raise_on_malformed_state():
    """A render against a state object whose to_dict() raises must
    return an empty body, not propagate the exception — /metrics is
    a hot-path scrape target and downtime there hides real failures."""
    class BrokenState:
        def to_dict(self):
            raise RuntimeError("intentional")
    body, ct = metrics.render(BrokenState())
    assert isinstance(body, (bytes, bytearray))
    assert "text/plain" in ct


# These tests require prometheus_client to actually be installed
# (which CI does in GitHub Actions). They're skipped on hosts without
# it so the suite stays green for contributors who haven't installed
# the optional dep yet.

try:
    import prometheus_client          # noqa: F401
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False


@pytest.mark.skipif(not HAS_PROMETHEUS,
                    reason="prometheus_client not installed")
def test_render_produces_known_metric_names():
    class FakeState:
        def to_dict(self):
            return {
                "switches": [
                    {"name": "sw1", "host": "10.0.0.1",
                     "vendor": "aruba_cx", "is_down": False},
                    {"name": "sw2", "host": "10.0.0.2",
                     "vendor": "cisco_ios", "is_down": True},
                ],
                "backup":  {"success_count": 10, "failed_count": 1,
                            "timestamp": "2026-05-12T12:00:00"},
                "scanner": {"device_count": 42,
                            "last_run": "2026-05-12T11:00:00"},
                "arp_last_run": {"loc1": "2026-05-12T10:00:00"},
            }
    metrics.inc("login_success_total", 3)
    metrics.inc("login_failures_total", 1)
    body, _ = metrics.render(FakeState())
    text = body.decode("utf-8")
    # Spot-check a handful of metric names so renames surface in CI.
    for needle in (
        "aruba_switches_up",
        "aruba_switches_down",
        "aruba_switches_total",
        "aruba_switch_reachable",
        "aruba_backup_success_count",
        "aruba_backup_failed_count",
        "aruba_backup_last_run_age_seconds",
        "aruba_scanner_device_count",
        "aruba_arp_last_run_age_seconds",
        "aruba_login_success_total",
        "aruba_login_failures_total",
    ):
        assert needle in text, f"missing metric: {needle}"
