"""
Device health poll — CPU / memory / temperature via SNMP (for threshold alerts).

Same shape as InterfacePollTask/L2DiscoveryTask: opt-in ([health]), polls every
known switch when include is blank, bounded pool + jitter + overlap guard, and
closes each worker's asyncio loop. Records metrics to the store and exposes
samples() for the threshold evaluator.
"""

from __future__ import annotations

import configparser
import logging
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List

from aruba_agent import health
from aruba_agent.snmp import close_thread_event_loop
from aruba_agent.tasks.interface_poll import _csv, _matches

log = logging.getLogger(__name__)

_METRICS = ("cpu", "memory", "temperature")


class HealthPollTask:
    def __init__(self, cfg: configparser.ConfigParser, state, snmp, store) -> None:
        h = cfg["health"] if "health" in cfg else {}
        self.state = state
        self.snmp = snmp
        self.store = store

        self.enabled        = (h.get("enabled", "false") or "false").lower() == "true"
        self.poll_seconds   = max(60, int(h.get("poll_seconds", "300") or "300"))
        self.max_workers    = max(1, int(h.get("max_workers", "8") or "8"))
        self.jitter_seconds = float(h.get("jitter_seconds", "2") or "2")
        self.record_metrics = (h.get("record_metrics", "true") or "true").lower() == "true"
        self.include = _csv(h.get("include", ""))
        self.exclude = _csv(h.get("exclude", ""))

        self._current: dict = {}         # name -> {cpu,memory,temperature,host}
        self._lock = threading.RLock()
        self._running = threading.Lock()

    def eligible(self) -> list:
        out = []
        for sw in list(self.state.switches.values()):
            if getattr(sw, "unmanaged", False):
                continue
            if getattr(sw, "monitor_mode", "auto") == "icmp":
                continue
            name, host = sw.name, sw.host
            if self.exclude and _matches(name, host, self.exclude):
                continue
            if self.include and not _matches(name, host, self.include):
                continue
            out.append(sw)
        return out

    def _poll_one(self, sw) -> int:
        try:
            return self._poll_one_inner(sw)
        finally:
            close_thread_event_loop()

    def _poll_one_inner(self, sw) -> int:
        if self.jitter_seconds > 0:
            time.sleep(random.uniform(0, self.jitter_seconds))
        vals = health.collect(self.snmp, sw.host,
                              vendor=getattr(sw, "vendor", "") or "",
                              profile_name=getattr(sw, "snmp_profile", "") or None)
        got = {k: v for k, v in vals.items() if v is not None}
        if not got:
            return 0
        vals["host"] = sw.host
        with self._lock:
            self._current[sw.name] = vals
        if self.record_metrics:
            for m in _METRICS:
                if vals.get(m) is not None:
                    self.store.record_metric(sw.name, f"health.{m}", vals[m])
        return len(got)

    def run(self) -> None:
        if not self.enabled or self.snmp is None:
            return
        if not self._running.acquire(blocking=False):
            log.warning("health poll: previous cycle still running — skipping tick")
            return
        try:
            elig = self.eligible()
            if not elig:
                return
            started = time.time()
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                counts = list(pool.map(self._poll_one, elig))
            log.info("health poll: %d switch(es), %d metric(s), %.1fs",
                     len(elig), sum(counts), time.time() - started)
        finally:
            self._running.release()

    # ── read side ───────────────────────────────────────────────────────────
    def get_current(self, name: str) -> dict:
        with self._lock:
            return dict(self._current.get(name, {}))

    def samples(self) -> List[dict]:
        """Current health readings as evaluator samples (instance='')."""
        out = []
        with self._lock:
            snapshot = dict(self._current)
        for name, vals in snapshot.items():
            host = vals.get("host", name)
            for m in _METRICS:
                if vals.get(m) is not None:
                    out.append({"device": name, "host": host, "metric": m,
                                "value": vals[m], "instance": ""})
        return out
