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

        self._prev: dict = {}       # name -> {ifIndex: (ts, hc_in, hc_out)}
        self._current: dict = {}    # name -> [rows incl. in_util/out_util]
        self._lock = threading.RLock()

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
            prev = self._prev.get(sw.name, {})
        current = []
        for idx, r in rows.items():
            p = prev.get(idx)
            elapsed = (now - p[0]) if p else 0
            in_util = ifc.compute_util(p[1] if p else None, r["hc_in"], elapsed, r["speed_mbps"])
            out_util = ifc.compute_util(p[2] if p else None, r["hc_out"], elapsed, r["speed_mbps"])
            row = dict(r); row["in_util"] = in_util; row["out_util"] = out_util
            current.append(row)
            if in_util is not None:
                self.store.record_metric(sw.name, f"if.{idx}.in_util", in_util,
                                         labels={"ifName": r["name"]})
            if out_util is not None:
                self.store.record_metric(sw.name, f"if.{idx}.out_util", out_util,
                                         labels={"ifName": r["name"]})
        newprev = {idx: (now, r["hc_in"], r["hc_out"]) for idx, r in rows.items()}
        current.sort(key=lambda x: _sortkey(x["ifIndex"]))
        with self._lock:
            self._prev[sw.name] = newprev
            self._current[sw.name] = current
        return len(current)

    def run(self) -> None:
        if not self.enabled:
            return
        if self.snmp is None:
            log.warning("interface poll: no SNMP agent — skipping")
            return
        elig = self.eligible()
        if not elig:
            return
        started = time.time()
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            counts = list(pool.map(self._poll_one, elig))
        log.info("interface poll: %d switch(es), %d interfaces, %.1fs",
                 len(elig), sum(counts), time.time() - started)

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
