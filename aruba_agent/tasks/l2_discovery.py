"""
Layer-2 discovery task — bridge MAC forwarding database (and, later, LLDP/CDP
neighbors). Separate from the interface poll on purpose: FDB/neighbor data
changes slowly and the walks are heavier, so this runs on its own slow cadence
(default hourly) to stay off the wire between sweeps.

Like InterfacePollTask it polls every switch the agent already knows (all of
state.switches) when [l2] include is blank — no CIDR to maintain — skipping
unmanaged and icmp-only hosts, and it has the same non-blocking overlap guard
so a long full-fleet sweep can't stack on itself.
"""

from __future__ import annotations

import configparser
import logging
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from aruba_agent import fdb
from aruba_agent.snmp import close_thread_event_loop
from aruba_agent.tasks.interface_poll import _csv, _matches

log = logging.getLogger(__name__)


class L2DiscoveryTask:
    def __init__(self, cfg: configparser.ConfigParser, state, snmp, store) -> None:
        l = cfg["l2"] if "l2" in cfg else {}
        self.state = state
        self.snmp  = snmp
        self.store = store

        self.enabled        = (l.get("enabled", "false") or "false").lower() == "true"
        # Floor 300s: this is discovery, not fault detection — hourly is typical.
        self.poll_seconds   = max(300, int(l.get("poll_seconds", "3600") or "3600"))
        self.max_workers    = max(1, int(l.get("max_workers", "8") or "8"))
        self.jitter_seconds = float(l.get("jitter_seconds", "2") or "2")
        self.include = _csv(l.get("include", ""))
        self.exclude = _csv(l.get("exclude", ""))

        self._counts: dict = {}          # name -> learned-MAC count (last sweep)
        self._lock = threading.RLock()
        self._running = threading.Lock()  # overlap guard

    # ── selection (mirrors InterfacePollTask) ──────────────────────────────────

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

    # ── discovery ───────────────────────────────────────────────────────────────

    def _discover_one(self, sw) -> int:
        try:
            return self._discover_one_inner(sw)
        finally:
            close_thread_event_loop()   # free the worker thread's loop fds

    def _discover_one_inner(self, sw) -> int:
        if self.jitter_seconds > 0:
            time.sleep(random.uniform(0, self.jitter_seconds))
        recs = fdb.collect(self.snmp, sw.host,
                           profile_name=getattr(sw, "snmp_profile", "") or None)
        if recs is None:
            log.debug("l2 discovery: %s (%s) no FDB (%s)", sw.name, sw.host,
                      getattr(self.snmp, "last_error", ""))
            return 0
        self.store.save_fdb(sw.name, recs)
        with self._lock:
            self._counts[sw.name] = len(recs)
        return len(recs)

    def run(self) -> None:
        if not self.enabled:
            return
        if self.snmp is None:
            log.warning("l2 discovery: no SNMP agent — skipping")
            return
        if not self._running.acquire(blocking=False):
            log.warning("l2 discovery: previous sweep still running — skipping "
                        "this tick (raise [l2] poll_seconds or max_workers)")
            return
        try:
            elig = self.eligible()
            if not elig:
                return
            started = time.time()
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                counts = list(pool.map(self._discover_one, elig))
            log.info("l2 discovery: %d switch(es), %d MACs, %.1fs",
                     len(elig), sum(counts), time.time() - started)
        finally:
            self._running.release()

    # ── read side ───────────────────────────────────────────────────────────────

    def search(self, mac_query: str, *, edge_only: bool = True, limit: int = 200) -> list:
        """Look up a MAC (any spelling). Returns store rows, edge port first.
        edge_only keeps just the lowest-port_mac_count hit per device (the
        access port), hiding uplink/trunk learn entries."""
        canon = fdb.normalize_mac(mac_query)
        if not canon:
            return []
        rows = self.store.search_fdb(canon, limit=limit) or []
        if not edge_only:
            return rows
        best = {}
        for r in rows:
            d = r.get("device")
            if d not in best or (r.get("port_mac_count", 1e9)
                                 < best[d].get("port_mac_count", 1e9)):
                best[d] = r
        return sorted(best.values(), key=lambda r: r.get("port_mac_count", 1e9))

    def summary(self) -> dict:
        with self._lock:
            return dict(self._counts)
