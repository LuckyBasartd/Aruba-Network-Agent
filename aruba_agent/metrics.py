"""
Prometheus /metrics exposition.

Why this exists
---------------
Operators running this agent in a real fleet want their existing
Prometheus + Grafana / Alertmanager stack to see what's happening
without having to scrape the dashboard HTML or tail the journal.
This module produces a standard text-format /metrics body the agent
can serve from a Flask route.

Two flavours of metrics live here:

1. **State-derived metrics** are computed on demand from AgentState
   each time /metrics is scraped — switches_up, last_backup_age, etc.
   No counters to keep in sync; the dashboard and Prometheus see the
   same numbers because they both read AgentState.to_dict().

2. **Process counters** track events that don't live in AgentState:
   login successes, failures, throttle hits. The Flask routes
   increment these via the small helpers exposed below.

prometheus-client is the canonical library and what every existing
Grafana dashboard expects. It's a single small package with no
heavy deps (~50 KB). Lazy-imported inside the renderer so a host
that doesn't have it installed yet doesn't fail to boot the agent.

Scrape contract
---------------
``render(state)`` returns (body_bytes, content_type). Caller is the
Flask route in web/app.py:

    body, ct = metrics.render(state)
    return Response(body, mimetype=ct)
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional


log = logging.getLogger(__name__)


# Process-wide counters. We keep our own little dict (rather than the
# real prometheus_client Counter type) so this module imports cleanly
# even when prometheus-client isn't installed. The render() call below
# lazily builds the real types on demand.
_counter_lock = threading.Lock()
_counters: dict = {
    "login_failures_total":    0,
    "login_throttled_total":   0,
    "login_success_total":     0,
    "manual_trigger_total":    0,   # union: backup + scan + arp
}


def inc(name: str, by: int = 1) -> None:
    """Increment a named process counter. Unknown names are dropped
    silently — better than crashing a hot login path because a metric
    rename slipped through unnoticed."""
    with _counter_lock:
        if name in _counters:
            _counters[name] += by


def _snapshot_counters() -> dict:
    with _counter_lock:
        return dict(_counters)


# ─── renderer ────────────────────────────────────────────────────────────────

# Default content-type for Prometheus text format 0.0.4. Hard-coded so
# we don't have to import prometheus_client just to read its constant.
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def render(state) -> tuple[bytes, str]:
    """
    Build the text-format /metrics body from ``state`` (an AgentState
    instance). Never raises — if prometheus-client is missing or the
    state shape is unexpected, returns an empty body + the standard
    content type so the scraper sees a normal "no data" response and
    Prometheus's "up" gauge stays 1.
    """
    try:
        from prometheus_client import (
            CollectorRegistry, Counter, Gauge, generate_latest,
        )
    except ImportError as exc:
        log.warning("metrics: prometheus_client not installed (%s) — "
                    "/metrics will return empty", exc)
        return (b"", CONTENT_TYPE)

    try:
        reg = CollectorRegistry()
        snap = state.to_dict()

        # ── switches ─────────────────────────────────────────────────────────
        switches = snap.get("switches", [])
        up_g = Gauge(
            "aruba_switches_up",
            "Number of monitored switches currently reachable.",
            registry=reg,
        )
        down_g = Gauge(
            "aruba_switches_down",
            "Number of monitored switches currently unreachable.",
            registry=reg,
        )
        total_g = Gauge(
            "aruba_switches_total",
            "Total number of monitored switches.",
            registry=reg,
        )
        up   = sum(1 for s in switches if not s.get("is_down"))
        down = sum(1 for s in switches if s.get("is_down"))
        up_g.set(up)
        down_g.set(down)
        total_g.set(len(switches))

        # Per-switch reachability — labelled, so dashboards can show
        # individual flap charts. 0 = down, 1 = up. Bounded by fleet
        # size (we don't expect > a few hundred series here).
        sw_state = Gauge(
            "aruba_switch_reachable",
            "Per-switch reachability (1=up, 0=down).",
            labelnames=["name", "host", "vendor"],
            registry=reg,
        )
        for s in switches:
            sw_state.labels(
                name=s.get("name", "?"),
                host=s.get("host", "?"),
                vendor=s.get("vendor", "") or "unknown",
            ).set(0 if s.get("is_down") else 1)

        # ── backup ───────────────────────────────────────────────────────────
        backup = snap.get("backup") or {}
        b_ok = Gauge(
            "aruba_backup_success_count",
            "Successful backups in the most recent backup run.",
            registry=reg,
        )
        b_fail = Gauge(
            "aruba_backup_failed_count",
            "Failed backups in the most recent backup run.",
            registry=reg,
        )
        b_age = Gauge(
            "aruba_backup_last_run_age_seconds",
            "Seconds since the most recent backup run started "
            "(0 if backup has never run).",
            registry=reg,
        )
        b_ok.set(int(backup.get("success_count") or 0))
        b_fail.set(int(backup.get("failed_count") or 0))
        b_age.set(_age_seconds(backup.get("timestamp")))

        # ── scanner ──────────────────────────────────────────────────────────
        scanner = snap.get("scanner") or {}
        s_count = Gauge(
            "aruba_scanner_device_count",
            "Devices discovered in the most recent scan.",
            registry=reg,
        )
        s_age = Gauge(
            "aruba_scanner_last_run_age_seconds",
            "Seconds since the most recent scanner run.",
            registry=reg,
        )
        s_count.set(int(scanner.get("device_count") or 0))
        s_age.set(_age_seconds(scanner.get("last_run")))

        # ── ARP per-location ─────────────────────────────────────────────────
        arp = snap.get("arp_last_run") or {}
        arp_age = Gauge(
            "aruba_arp_last_run_age_seconds",
            "Seconds since the most recent ARP discovery run, per location.",
            labelnames=["location"],
            registry=reg,
        )
        for loc, ts in arp.items():
            arp_age.labels(location=loc).set(_age_seconds(ts))

        # ── process counters ─────────────────────────────────────────────────
        counters = _snapshot_counters()
        login_ok = Counter(
            "aruba_login_success_total",
            "Total successful logins since agent start.",
            registry=reg,
        )
        login_bad = Counter(
            "aruba_login_failures_total",
            "Total failed login attempts since agent start.",
            registry=reg,
        )
        login_throttled = Counter(
            "aruba_login_throttled_total",
            "Total login attempts blocked by the rate limiter since agent start.",
            registry=reg,
        )
        manual = Counter(
            "aruba_manual_trigger_total",
            "Total operator-triggered task runs since agent start "
            "(backup + scanner + ARP combined).",
            registry=reg,
        )
        # prometheus_client Counters can't be set() directly — emulate
        # by incrementing once with the cumulative value. This keeps
        # the rate() calculation correct across scrapes.
        login_ok.inc(counters["login_success_total"])
        login_bad.inc(counters["login_failures_total"])
        login_throttled.inc(counters["login_throttled_total"])
        manual.inc(counters["manual_trigger_total"])

        return (generate_latest(reg), CONTENT_TYPE)
    except Exception as exc:                                  # pragma: no cover
        log.warning("metrics: render failed (%s) — returning empty body", exc)
        return (b"", CONTENT_TYPE)


def _age_seconds(ts_iso: Optional[str]) -> float:
    """Return seconds since ``ts_iso`` (an ISO-8601 timestamp), or 0
    if the timestamp is None or unparseable. Prometheus prefers a
    finite number to a missing series for "this never ran"."""
    if not ts_iso:
        return 0.0
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(ts_iso)
        return max(0.0, time.time() - dt.timestamp())
    except (TypeError, ValueError):
        return 0.0
