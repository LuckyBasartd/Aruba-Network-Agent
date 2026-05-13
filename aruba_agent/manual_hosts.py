"""
Manually-added monitored hosts.

Why this exists
---------------
The scanner discovers switches by ICMP-sweeping the [scanner] subnets,
optionally REST-verifying each responder. That handles the bulk case
(campus switches inside known supernet) but misses two real situations:

  1. Hosts outside the configured subnets that the operator still
     wants monitored — out-of-band management of a remote stack, an
     edge device, a partner-org router we have visibility into.

  2. Hosts that don't accept the full management-plane stack —
     SNMP-read-only devices, devices that only respond to ping
     because of an ACL the operator can't change.

This module is the store for those manually-pinned hosts plus their
per-host "monitor_mode" preference. The SwitchMonitor reads
``get_mode(host)`` and dispatches accordingly:

    icmp     — ping only every 30 s, no SNMP, no driver, no backup
    snmp_ro  — SNMPv3 reachability polls, but never invoke a vendor
               driver (no backup attempts, no `show arp`)
    snmp_rw  — current default behaviour (SNMP + REST/SSH backups)
    auto     — agent decides per host based on what works

Storage
-------
JSON at /var/lib/aruba-agent/manual_hosts.json (mode 600, agent
owned). Atomic writes via tempfile + os.replace, mirroring the
local_auth + api_tokens stores.

Threading
---------
RLock-guarded. Safe to call from any thread.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


log = logging.getLogger(__name__)


# The four valid monitor modes. Anything else falls through to "auto"
# so a typo in an operator-edited file doesn't brick monitoring.
VALID_MODES: Tuple[str, ...] = ("icmp", "snmp_ro", "snmp_rw", "auto")

# Default mode for a manually-added host when the operator doesn't
# specify one. "auto" matches the scanner-discovered behaviour.
DEFAULT_MODE = "auto"


# ─── store ────────────────────────────────────────────────────────────────────

class ManualHostsStore:
    """
    JSON-backed manual-host registry.

    File schema:
        {
          "hosts": [
            {
              "name":         "remote-edge-01",
              "host":         "10.99.0.5",
              "monitor_mode": "icmp",
              "snmp_profile": "",          # optional pin
              "description":  "ISP demarc — ping only",
              "added_by":     "mvieira",
              "created":      "2026-05-12T18:30:00"
            }, ...
          ]
        }
    """

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._lock = threading.RLock()
        self._hosts: Dict[str, dict] = {}      # keyed by name
        self._load()

    # ─── persistence ─────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._path.exists():
            log.info("Manual hosts: no store at %s — starting empty", self._path)
            return
        try:
            with self._path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            for h in data.get("hosts", []):
                name = h.get("name")
                host = h.get("host")
                if not name or not host:
                    continue
                # Coerce any unknown mode into the safe default so a
                # hand-edited file with a typo doesn't disable a host.
                if h.get("monitor_mode") not in VALID_MODES:
                    h["monitor_mode"] = DEFAULT_MODE
                self._hosts[name] = h
            log.info("Manual hosts: loaded %d host(s) from %s",
                     len(self._hosts), self._path)
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Manual hosts: could not read %s (%s) — starting empty",
                        self._path, exc)

    def _save(self) -> None:
        """Atomic save, mode 600. Caller already holds self._lock."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=".manual-hosts-", suffix=".tmp",
            dir=str(self._path.parent),
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                json.dump(
                    {"hosts": list(self._hosts.values())},
                    tmp, indent=2, sort_keys=True,
                )
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_name, self._path)
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    # ─── CRUD ────────────────────────────────────────────────────────────────

    def add(
        self,
        name:         str,
        host:         str,
        monitor_mode: str = DEFAULT_MODE,
        snmp_profile: str = "",
        description:  str = "",
        added_by:     str = "",
    ) -> bool:
        """Create a new manual host. Returns False if the name is taken
        or the inputs are invalid."""
        name = (name or "").strip()
        host = (host or "").strip()
        if not name or not host:
            return False
        if monitor_mode not in VALID_MODES:
            monitor_mode = DEFAULT_MODE

        with self._lock:
            if name in self._hosts:
                return False
            self._hosts[name] = {
                "name":         name,
                "host":         host,
                "monitor_mode": monitor_mode,
                "snmp_profile": (snmp_profile or "").strip(),
                "description":  (description or "").strip(),
                "added_by":     added_by or "?",
                "created":      datetime.now().isoformat(timespec="seconds"),
            }
            self._save()
        log.info("Manual host added: name=%s host=%s mode=%s by=%s",
                 name, host, monitor_mode, added_by)
        return True

    def update(
        self,
        name:         str,
        monitor_mode: Optional[str] = None,
        snmp_profile: Optional[str] = None,
        description:  Optional[str] = None,
        host:         Optional[str] = None,
    ) -> bool:
        """
        Partial update of an existing host. None means "leave this
        field alone." Returns False if the host isn't tracked.
        """
        with self._lock:
            existing = self._hosts.get(name)
            if existing is None:
                return False
            if monitor_mode is not None:
                if monitor_mode not in VALID_MODES:
                    return False
                existing["monitor_mode"] = monitor_mode
            if snmp_profile is not None:
                existing["snmp_profile"] = (snmp_profile or "").strip()
            if description is not None:
                existing["description"] = (description or "").strip()
            if host is not None and host.strip():
                existing["host"] = host.strip()
            self._save()
        log.info("Manual host updated: name=%s", name)
        return True

    def remove(self, name: str) -> bool:
        with self._lock:
            if name not in self._hosts:
                return False
            del self._hosts[name]
            self._save()
        log.info("Manual host removed: name=%s", name)
        return True

    # ─── lookups ─────────────────────────────────────────────────────────────

    def list_hosts(self) -> List[dict]:
        """Return all manual hosts. Dashboard renders this verbatim."""
        with self._lock:
            return list(self._hosts.values())

    def get_mode(self, host: str) -> Optional[str]:
        """
        Return the monitor_mode for the given host (IP or hostname),
        or None if the host isn't in the manual registry. The
        SwitchMonitor uses this to decide how aggressively to poll.
        """
        with self._lock:
            for h in self._hosts.values():
                if h.get("host") == host:
                    return h.get("monitor_mode", DEFAULT_MODE)
            return None

    def get_snmp_profile(self, host: str) -> str:
        """Return the per-host SNMP profile pin from the manual store,
        or '' if not set. Useful for SNMP-RO hosts that only authenticate
        against a specific monitoring profile."""
        with self._lock:
            for h in self._hosts.values():
                if h.get("host") == host:
                    return h.get("snmp_profile", "")
            return ""
