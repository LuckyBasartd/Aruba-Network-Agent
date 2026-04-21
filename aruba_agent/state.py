"""
Shared in-memory state store.

All monitors and tasks write here; the web UI reads from here via to_dict().
Thread-safe via a single RLock.

AP Registry persistence
-----------------------
The AP inventory (name + IP) is written to a JSON file on disk whenever a new
AP is first discovered.  On startup the file is reloaded so the list survives
service restarts.  APs are never auto-removed — manual deletion from the file
is the only way to remove an entry.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

log = logging.getLogger(__name__)


@dataclass
class SwitchState:
    name:       str
    host:       str
    hostname:   str               = ""   # resolved from switch API, may differ from name/IP
    is_down:    bool              = False
    failures:   int               = 0
    last_seen:  Optional[datetime] = None
    last_event: str               = "Initializing"


@dataclass
class ApEvent:
    timestamp: datetime
    ap_name:   str
    state:     str        # "up" | "down"
    source_ip: str


@dataclass
class BackupRun:
    timestamp:      Optional[datetime] = None
    success_count:  int                = 0
    failed_count:   int                = 0
    failed_devices: List[dict]         = field(default_factory=list)


class AgentState:
    """Singleton-style shared state.  Pass one instance to every component."""

    def __init__(self, ap_registry_path: str = "/var/lib/aruba-agent/ap_registry.json") -> None:
        self._lock = threading.RLock()

        # Switch reachability monitor
        self.switches: Dict[str, SwitchState] = {}

        # AP syslog events — keep last 200
        self.ap_events: deque[ApEvent] = deque(maxlen=200)

        # AP heartbeat tracking — {ap_name: last_seen_datetime}
        # Used by the syslog monitor to detect APs that stop checking in
        self.ap_last_seen: Dict[str, datetime] = {}
        self.ap_is_down:   Dict[str, bool]     = {}

        # Persistent AP registry — {ap_name: {"ip": str, "first_seen": iso_str}}
        # Loaded from disk on startup; written whenever a new AP is discovered.
        # Entries are never auto-removed.
        self._ap_registry_path = ap_registry_path
        self.ap_registry: Dict[str, Dict[str, str]] = {}
        self._load_ap_registry()

        # Most recent config-backup run
        self.backup: BackupRun = BackupRun()

        # Network scanner
        self.device_inventory: List[Dict[str, str]] = []   # [{ip, name}, ...]
        self.scanner_last_run: Optional[datetime]   = None

        # ARP discovery — per-location last-run timestamps
        self.arp_last_run: Dict[str, Optional[datetime]] = {}

    # --------------------------------------------------- AP registry (disk)

    def _load_ap_registry(self) -> None:
        """Load the persistent AP registry from disk into memory on startup."""
        if not os.path.exists(self._ap_registry_path):
            log.info("AP registry not found at %s — starting fresh", self._ap_registry_path)
            return
        try:
            with open(self._ap_registry_path) as f:
                self.ap_registry = json.load(f)
            log.info("AP registry loaded: %d APs from %s",
                     len(self.ap_registry), self._ap_registry_path)
            # Re-hydrate ap_last_seen so the heartbeat monitor works immediately
            for ap_name, entry in self.ap_registry.items():
                if ap_name not in self.ap_last_seen:
                    try:
                        self.ap_last_seen[ap_name] = datetime.fromisoformat(entry["last_seen"])
                    except (KeyError, ValueError):
                        pass
                if ap_name not in self.ap_is_down:
                    self.ap_is_down[ap_name] = entry.get("is_down", False)
        except Exception as exc:
            log.error("AP registry load failed (%s): %s — starting fresh", self._ap_registry_path, exc)

    def _save_ap_registry(self) -> None:
        """Write the current AP registry to disk (called under self._lock)."""
        try:
            os.makedirs(os.path.dirname(self._ap_registry_path) or ".", exist_ok=True)
            with open(self._ap_registry_path, "w") as f:
                json.dump(self.ap_registry, f, indent=2)
        except Exception as exc:
            log.error("AP registry save failed: %s", exc)

    def register_ap(self, ap_name: str, source_ip: str) -> bool:
        """
        Record an AP in the persistent registry if it hasn't been seen before.
        Returns True if this is a newly registered AP, False if already known.
        The registry is flushed to disk only on new discoveries.
        """
        with self._lock:
            if ap_name in self.ap_registry:
                return False
            now = datetime.now()
            self.ap_registry[ap_name] = {
                "ip":          source_ip,
                "first_seen":  now.isoformat(),
                "last_seen":   now.isoformat(),
                "is_down":     False,
            }
            log.info("New AP registered: %s (ip=%s) — saving registry", ap_name, source_ip)
            self._save_ap_registry()
            return True

    def update_ap_registry(self, ap_name: str, source_ip: str, is_down: bool) -> None:
        """Keep last_seen / is_down current in the registry and flush to disk."""
        with self._lock:
            if ap_name not in self.ap_registry:
                return
            self.ap_registry[ap_name]["last_seen"] = datetime.now().isoformat()
            self.ap_registry[ap_name]["is_down"]   = is_down
            if source_ip and source_ip != "heartbeat-timeout":
                self.ap_registry[ap_name]["ip"] = source_ip
            self._save_ap_registry()

    # -------------------------------------------------------- switch helpers

    def register_switch(self, name: str, host: str) -> None:
        with self._lock:
            if name not in self.switches:
                self.switches[name] = SwitchState(name=name, host=host)

    def update_switch(self, name: str, **kwargs) -> None:
        with self._lock:
            if name in self.switches:
                for k, v in kwargs.items():
                    setattr(self.switches[name], k, v)

    # --------------------------------------------------------- AP event log

    def add_ap_event(self, ap_name: str, state: str, source_ip: str) -> None:
        with self._lock:
            self.ap_events.appendleft(
                ApEvent(timestamp=datetime.now(), ap_name=ap_name,
                        state=state, source_ip=source_ip)
            )
            if state == "up":
                self.ap_last_seen[ap_name] = datetime.now()
                self.ap_is_down[ap_name]   = False
            else:
                self.ap_is_down[ap_name] = True

    def mark_ap_down(self, ap_name: str) -> None:
        """Called by the heartbeat monitor when an AP stops checking in."""
        with self._lock:
            if not self.ap_is_down.get(ap_name, False):
                self.ap_is_down[ap_name] = True
                self.ap_events.appendleft(
                    ApEvent(timestamp=datetime.now(), ap_name=ap_name,
                            state="down", source_ip="heartbeat-timeout")
                )

    def get_stale_aps(self, cutoff: datetime) -> Dict[str, datetime]:
        """
        Return {ap_name: last_seen} for APs whose last heartbeat is older than
        *cutoff* and are not already flagged as down.
        Used by the heartbeat monitor without touching internal state directly.
        """
        with self._lock:
            return {
                name: ts
                for name, ts in self.ap_last_seen.items()
                if ts < cutoff and not self.ap_is_down.get(name, False)
            }

    def get_ap_summary(self) -> Dict[str, dict]:
        """Return current known AP states for the web UI."""
        with self._lock:
            return {
                name: {
                    "last_seen": ts.isoformat(),
                    "is_down":   self.ap_is_down.get(name, False),
                }
                for name, ts in self.ap_last_seen.items()
            }

    # --------------------------------------------------------- backup result

    def set_backup_result(self, success: int, failed: int, failed_devices: List[dict]) -> None:
        with self._lock:
            self.backup = BackupRun(
                timestamp      = datetime.now(),
                success_count  = success,
                failed_count   = failed,
                failed_devices = failed_devices,
            )

    # ------------------------------------------------------ scanner / ARP

    def set_device_inventory(self, devices: List[Dict[str, str]]) -> None:
        with self._lock:
            self.device_inventory  = devices
            self.scanner_last_run  = datetime.now()

    def set_arp_last_run(self, location: str) -> None:
        with self._lock:
            self.arp_last_run[location] = datetime.now()

    # ----------------------------------------------- serialise for web API

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "switches": [
                    {
                        "name":       s.name,
                        "host":       s.host,
                        "hostname":   s.hostname or s.name,
                        "is_down":    s.is_down,
                        "failures":   s.failures,
                        "last_seen":  s.last_seen.isoformat() if s.last_seen else None,
                        "last_event": s.last_event,
                        "status":     "DOWN" if s.is_down else "UP",
                    }
                    for s in self.switches.values()
                ],
                "ap_events": [
                    {
                        "timestamp": e.timestamp.isoformat(),
                        "ap_name":   e.ap_name,
                        "state":     e.state,
                        "source_ip": e.source_ip,
                    }
                    for e in self.ap_events
                ],
                "backup": {
                    "timestamp":      self.backup.timestamp.isoformat()
                                      if self.backup.timestamp else None,
                    "success_count":  self.backup.success_count,
                    "failed_count":   self.backup.failed_count,
                    "failed_devices": self.backup.failed_devices,
                },
                "scanner": {
                    "last_run":     self.scanner_last_run.isoformat()
                                    if self.scanner_last_run else None,
                    "device_count": len(self.device_inventory),
                    "devices":      self.device_inventory,
                },
                "arp_last_run": {
                    loc: ts.isoformat() if ts else None
                    for loc, ts in self.arp_last_run.items()
                },
                "ap_inventory": [
                    {
                        "ap_name":    name,
                        "ip":         entry.get("ip", ""),
                        "first_seen": entry.get("first_seen", ""),
                        "last_seen":  entry.get("last_seen", ""),
                        "is_down":    entry.get("is_down", False),
                        "status":     "DOWN" if entry.get("is_down", False) else "UP",
                    }
                    for name, entry in sorted(self.ap_registry.items())
                ],
            }
