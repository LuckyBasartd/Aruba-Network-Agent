"""
Interface statistics poll task (SolarWinds NPM parity).

Every ``poll_seconds`` (default 300, floor 60), walk ifXTable on each eligible
switch via SNMP GETBULK, compute per-interface utilization from counter deltas,
record time-series metrics (in/out util %) to the Store, and keep a current
snapshot in memory for the UI.

Anti-chatter (see INTERFACE_MONITORING_SPEC.md):
  * slow cadence (separate from the 30s reachability poll)
  * bounded worker pool caps simultaneous switch polls
  * small random jitter per switch avoids synchronized bursts
  * physical interfaces only by default (fewer varbinds)
  * opt-in + include/exclude scoping; reuses the host's SNMP profile;
    skips icmp-only / unmanaged hosts.
"""

from __future__ import annotations

import configparser
import ipaddress
import logging
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from aruba_agent import interfaces as ifc
from aruba_agent.snmp import close_thread_event_loop

log = logging.getLogger(__name__)


def _csv(v: str) -> List[str]:
    return [x.strip() for x in (v or "").replace(" ", ",").split(",") if x.strip()]


def _matches(name: str, host: str, patterns: List[str]) -> bool:
    for p in patterns:
        if p == name or p == host:
            return True
        if "/" in p:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(p, strict=False):
                    return True
            except ValueError:
                pass
    return False


class InterfacePollTask:
    def __init__(self, cfg: configparser.ConfigParser, state, snmp, store) -> None:
        i = cfg["interfaces"] if "interfaces" in cfg else {}
        self.state = state
        self.snmp  = snmp
        self.store = store

        self.enabled       = (i.get("enabled", "false") or "false").lower() == "true"
        self.poll_seconds  = max(60, int(i.get("poll_seconds", "300") or "300"))
        self.max_workers   = max(1, int(i.get("max_workers", "8") or "8"))
        self.physical_only = (i.get("physical_only", "true") or "true").lower() == "true"
        self.jitter_seconds = float(i.get("jitter_seconds", "2") or "2")
        self.include = _csv(i.get("include", ""))
        self.exclude = _csv(i.get("exclude", ""))
        # Metrics volume controls. Recording every port's util every cycle
        # floods the time-series store (millions of docs) — most ports sit at
        # 0%. Off-by-default zero recording keeps only meaningful samples;
        # record_metrics=false disables time-series entirely (e.g. small box).
        self.record_metrics   = (i.get("record_metrics", "true") or "true").lower() == "true"
        self.record_zero_util = (i.get("record_zero_util", "false") or "false").lower() == "true"

        self._prev: dict = {}       # name -> {ifIndex: (ts, hc_in, hc_out)}
        self._current: dict = {}    # name -> [rows incl. in_util/out_util]
        self._lock = threading.RLock()
        self._running = threading.Lock()   # overlap guard: one sweep at a time

    # ── selection ─────────────────────────────────────────────────────────────

    def eligible(self) -> list:
        out = []
        for sw in list(self.state.switches.values()):
            if getattr(sw, "unmanaged", False):
                continue
            if getattr(sw, "monitor_mode", "auto") == "icmp":
                continue                      # ping-only hosts: no SNMP
            name, host = sw.name, sw.host
            if self.exclude and _matches(name, host, self.exclude):
                continue
            if self.include and not _matches(name, host, self.include):
                continue
            out.append(sw)
        return out

    # ── polling ───────────────────────────────────────────────────────────────

    def _poll_one(self, sw) -> int:
        try:
            return self._poll_one_inner(sw)
        finally:
            # Pool worker threads are recreated each sweep; close this thread's
            # asyncio loop so its socketpair fds don't leak (see snmp.py).
            close_thread_event_loop()

    def _poll_one_inner(self, sw) -> int:
        if self.jitter_seconds > 0:
            time.sleep(random.uniform(0, self.jitter_seconds))
        rows = ifc.collect(self.snmp, sw.host,
                           profile_name=getattr(sw, "snmp_profile", "") or None,
                           physical_only=self.physical_only)
        if rows is None:
            log.debug("interface poll: %s (%s) no data (%s)", sw.name, sw.host,
                      getattr(self.snmp, "last_error", ""))
            return 0
        now = time.time()
        with self._lock:
            prev = self._prev.get(sw.name)
        if prev is None:                        # cold: hydrate from the store so
            prev = self._load_prev(sw.name)     # util survives an agent restart
        current = []
        for idx, r in rows.items():
            p = prev.get(idx)
            elapsed = (now - p[0]) if p else 0
            in_util = ifc.compute_util(p[1] if p else None, r["hc_in"], elapsed, r["speed_mbps"])
            out_util = ifc.compute_util(p[2] if p else None, r["hc_out"], elapsed, r["speed_mbps"])
            row = dict(r); row["in_util"] = in_util; row["out_util"] = out_util
            current.append(row)
            if self.record_metrics:
                if in_util is not None and (self.record_zero_util or in_util > 0):
                    self.store.record_metric(sw.name, f"if.{idx}.in_util", in_util,
                                             labels={"ifName": r["name"]})
                if out_util is not None and (self.record_zero_util or out_util > 0):
                    self.store.record_metric(sw.name, f"if.{idx}.out_util", out_util,
                                             labels={"ifName": r["name"]})
        newprev = {idx: (now, r["hc_in"], r["hc_out"]) for idx, r in rows.items()}
        current.sort(key=lambda x: _sortkey(x["ifIndex"]))
        with self._lock:
            self._prev[sw.name] = newprev
            self._current[sw.name] = current
        self._save_prev(sw.name, newprev)       # restart-safe (Mongo backend)
        return len(current)

    # ── counter persistence (restart-safe utilization) ─────────────────────────

    def _load_prev(self, name: str) -> dict:
        """Load the last raw counter snapshot for one switch from the store and
        coerce it back to {ifIndex: (ts_float, hc_in_int, hc_out_int)}. Returns
        {} on any backend without support or on malformed data."""
        loader = getattr(self.store, "load_counters", None)
        if loader is None:
            return {}
        try:
            raw = loader(name) or {}
        except Exception:
            return {}
        out = {}
        for idx, triple in raw.items():
            try:
                ts, a, b = triple
                out[idx] = (float(ts), int(a), int(b))
            except (TypeError, ValueError):
                continue
        with self._lock:                         # cache so we don't reload next cycle
            self._prev[name] = out
        return out

    def _save_prev(self, name: str, newprev: dict) -> None:
        saver = getattr(self.store, "save_counters", None)
        if saver is None:
            return
        try:
            saver(name, {idx: [ts, hc_in, hc_out]
                         for idx, (ts, hc_in, hc_out) in newprev.items()})
        except Exception as exc:
            log.debug("interface poll: save_counters failed for %s (%s)", name, exc)

    def run(self) -> None:
        if not self.enabled:
            return
        if self.snmp is None:
            log.warning("interface poll: no SNMP agent — skipping")
            return
        # Overlap guard: the scheduler fires a fresh thread every poll_seconds,
        # but a full-fleet sweep can outlast one interval. Never stack sweeps —
        # a second concurrent poll would double the SNMP load and record util
        # over a too-short window (noise). If the previous cycle is still
        # running, skip this tick and let it finish.
        if not self._running.acquire(blocking=False):
            log.warning("interface poll: previous cycle still running — skipping "
                        "this tick (raise [interfaces] poll_seconds or max_workers)")
            return
        try:
            elig = self.eligible()
            if not elig:
                return
            started = time.time()
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                counts = list(pool.map(self._poll_one, elig))
            log.info("interface poll: %d switch(es), %d interfaces, %.1fs",
                     len(elig), sum(counts), time.time() - started)
        finally:
            self._running.release()

    # ── read side (for the web API / CLI) ──────────────────────────────────────

    def get_current(self, name: str) -> list:
        with self._lock:
            return list(self._current.get(name, []))

    def summary(self) -> dict:
        with self._lock:
            return {n: len(rows) for n, rows in self._current.items()}


def _sortkey(ifindex: str):
    try:
        return (0, int(ifindex))
    except (TypeError, ValueError):
        return (1, str(ifindex))
