"""
Shared in-memory state store.

All monitors and tasks write here; the web UI reads from here via to_dict().
Thread-safe via a single RLock.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


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

    def __init__(self) -> None:
        self._lock = threading.RLock()

        # Switch reachability monitor
        self.switches: Dict[str, SwitchState] = {}

        # AP syslog events — keep last 200
        self.ap_events: deque[ApEvent] = deque(maxlen=200)

        # Most recent config-backup run
        self.backup: BackupRun = BackupRun()

        # Network scanner
        self.device_inventory: List[Dict[str, str]] = []   # [{ip, name}, ...]
        self.scanner_last_run: Optional[datetime]   = None

        # ARP discovery — per-location last-run timestamps
        self.arp_last_run: Dict[str, Optional[datetime]] = {}

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
            }
