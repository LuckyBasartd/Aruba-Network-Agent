"""
Shared in-memory state store, with optional on-disk persistence.

All monitors and tasks write here; the web UI reads from here via to_dict().
Thread-safe via a single RLock.

Persistence
-----------
If `AgentState` is constructed with a `snapshot_path`, the state is loaded
from that JSON file at startup (if it exists) and written back atomically
on every "big" event:

    * a switch is registered (new entry)
    * a switch transitions UP <-> DOWN
    * the network scanner finishes (device inventory + last-run timestamp)
    * config backup finishes (success/failure summary)
    * an ARP-discovery run finishes (per-location timestamp)

Cosmetic updates from the reachability poller (every 30 s ticking
`last_seen` / `failures`) deliberately do NOT trigger a write — they
would burn through disk I/O at ~6 Hz with no real benefit.

Why this matters: the agent is a long-running systemd service, but the
host can reboot, the unit can be restarted, or the process can crash.
Without a snapshot, every restart would zero out the inventory of
discovered switches, the most recent backup result, and the scanner /
ARP timestamps shown on the dashboard. With it, the dashboard comes
back exactly the way the operator left it.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger(__name__)


# ─── helpers ───────────────────────────────────────────────────────────────────

def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


# ─── dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class SwitchState:
    name:       str
    host:       str
    hostname:   str               = ""   # resolved from switch API, may differ from name/IP
    vendor:     str               = ""   # "aruba_cx" / "cisco_ios" / "arista_eos" / ...
    is_down:    bool              = False
    failures:   int               = 0
    last_seen:  Optional[datetime] = None
    last_event: str               = "Initializing"


@dataclass
class BackupRun:
    timestamp:      Optional[datetime] = None
    success_count:  int                = 0
    failed_count:   int                = 0
    failed_devices: List[dict]         = field(default_factory=list)


# ─── main store ────────────────────────────────────────────────────────────────

class AgentState:
    """
    Singleton-style shared state. Pass one instance to every component.

    Parameters
    ----------
    snapshot_path : str | Path | None
        If given, state will be persisted as JSON to this path and
        rehydrated from it at startup. Pass `None` for ephemeral
        (test / dev) use.
    """

    def __init__(self, snapshot_path: Optional[str] = None) -> None:
        self._lock = threading.RLock()

        self._snapshot_path: Optional[Path] = (
            Path(snapshot_path) if snapshot_path else None
        )

        # Switch reachability monitor
        self.switches: Dict[str, SwitchState] = {}

        # Most recent config-backup run
        self.backup: BackupRun = BackupRun()

        # Network scanner
        self.device_inventory: List[Dict[str, str]] = []   # [{ip, name}, ...]
        self.scanner_last_run: Optional[datetime]   = None

        # ARP discovery — per-location last-run timestamps
        self.arp_last_run: Dict[str, Optional[datetime]] = {}

        # Rehydrate if a snapshot exists
        if self._snapshot_path is not None:
            self._load()

    # ─── persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        """
        Best-effort load. Never raises — a missing or corrupt snapshot
        just means we start with empty state.
        """
        path = self._snapshot_path
        if path is None or not path.exists():
            log.info("No snapshot at %s — starting with empty state", path)
            return

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Could not load snapshot %s (%s) — starting empty", path, exc)
            return

        try:
            # switches
            for entry in data.get("switches", []):
                name = entry.get("name")
                host = entry.get("host")
                if not name or not host:
                    continue
                self.switches[name] = SwitchState(
                    name       = name,
                    host       = host,
                    hostname   = entry.get("hostname", "") or "",
                    vendor     = entry.get("vendor",   "") or "",
                    is_down    = bool(entry.get("is_down", False)),
                    failures   = int(entry.get("failures", 0)),
                    last_seen  = _parse_iso(entry.get("last_seen")),
                    last_event = entry.get("last_event", "Restored from snapshot"),
                )

            # backup
            b = data.get("backup") or {}
            self.backup = BackupRun(
                timestamp      = _parse_iso(b.get("timestamp")),
                success_count  = int(b.get("success_count", 0)),
                failed_count   = int(b.get("failed_count", 0)),
                failed_devices = list(b.get("failed_devices", [])),
            )

            # scanner
            self.device_inventory = list(data.get("device_inventory", []))
            self.scanner_last_run = _parse_iso(data.get("scanner_last_run"))

            # arp
            self.arp_last_run = {
                loc: _parse_iso(ts)
                for loc, ts in (data.get("arp_last_run") or {}).items()
            }

            log.info(
                "Restored snapshot from %s (%d switches, %d devices)",
                path, len(self.switches), len(self.device_inventory),
            )
        except Exception as exc:  # pragma: no cover
            log.warning("Snapshot %s was malformed (%s) — starting empty", path, exc)
            # wipe whatever was partially populated to keep things consistent
            self.switches.clear()
            self.backup            = BackupRun()
            self.device_inventory  = []
            self.scanner_last_run  = None
            self.arp_last_run      = {}

    def _save(self) -> None:
        """
        Atomic save: write to a temp file in the same directory, then
        rename over the target. Caller already holds self._lock.
        """
        path = self._snapshot_path
        if path is None:
            return

        payload = {
            "switches": [
                {
                    "name":       s.name,
                    "host":       s.host,
                    "hostname":   s.hostname,
                    "vendor":     s.vendor,
                    "is_down":    s.is_down,
                    "failures":   s.failures,
                    "last_seen":  _iso(s.last_seen),
                    "last_event": s.last_event,
                }
                for s in self.switches.values()
            ],
            "backup": {
                "timestamp":      _iso(self.backup.timestamp),
                "success_count":  self.backup.success_count,
                "failed_count":   self.backup.failed_count,
                "failed_devices": self.backup.failed_devices,
            },
            "device_inventory": self.device_inventory,
            "scanner_last_run": _iso(self.scanner_last_run),
            "arp_last_run": {
                loc: _iso(ts) for loc, ts in self.arp_last_run.items()
            },
        }

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # NamedTemporaryFile in the same dir guarantees rename is atomic.
            fd, tmp_name = tempfile.mkstemp(
                prefix=".state-",
                suffix=".tmp",
                dir=str(path.parent),
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                    json.dump(payload, tmp, indent=2, sort_keys=True)
                    tmp.flush()
                    os.fsync(tmp.fileno())
                os.replace(tmp_name, path)
            except Exception:
                # mkstemp succeeded but write/rename failed — clean up
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
        except OSError as exc:
            log.warning("Could not persist state to %s: %s", path, exc)

    # -------------------------------------------------------- switch helpers

    def register_switch(self, name: str, host: str) -> None:
        with self._lock:
            if name not in self.switches:
                self.switches[name] = SwitchState(name=name, host=host)
                self._save()

    def get_vendor_for_host(self, host: str) -> str:
        """
        Return the cached vendor for a given IP / hostname (whatever
        was registered as ``host``), or '' if unknown.

        Used by tasks (backup, ARP, firmware) that operate on IPs and
        need to know which vendor's driver to use. The vendor is
        populated by the C3 detector during the SNMPv3 reachability
        poll and persisted in state.json.
        """
        with self._lock:
            for sw in self.switches.values():
                if sw.host == host:
                    return sw.vendor
            return ""

    def update_switch(self, name: str, **kwargs) -> None:
        """
        Apply attribute updates to a tracked switch.

        Persistence trigger: only when `is_down` actually flips. Every-poll
        ticks (last_seen, failures, last_event="Healthy") would otherwise
        rewrite the snapshot file at ~6 Hz across 200 switches.
        """
        with self._lock:
            sw = self.switches.get(name)
            if sw is None:
                return

            old_is_down = sw.is_down
            for k, v in kwargs.items():
                setattr(sw, k, v)

            new_is_down = sw.is_down
            if old_is_down != new_is_down:
                self._save()

    # --------------------------------------------------------- backup result

    def set_backup_result(self, success: int, failed: int, failed_devices: List[dict]) -> None:
        with self._lock:
            self.backup = BackupRun(
                timestamp      = datetime.now(),
                success_count  = success,
                failed_count   = failed,
                failed_devices = failed_devices,
            )
            self._save()

    # ------------------------------------------------------ scanner / ARP

    def set_device_inventory(self, devices: List[Dict[str, str]]) -> None:
        with self._lock:
            self.device_inventory  = devices
            self.scanner_last_run  = datetime.now()
            self._save()

    def set_arp_last_run(self, location: str) -> None:
        with self._lock:
            self.arp_last_run[location] = datetime.now()
            self._save()

    # ----------------------------------------------- serialise for web API

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "switches": [
                    {
                        "name":       s.name,
                        "host":       s.host,
                        "hostname":   s.hostname or s.name,
                        "vendor":     s.vendor or "",
                        "is_down":    s.is_down,
                        "failures":   s.failures,
                        "last_seen":  s.last_seen.isoformat() if s.last_seen else None,
                        "last_event": s.last_event,
                        "status":     "DOWN" if s.is_down else "UP",
                    }
                    for s in self.switches.values()
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
