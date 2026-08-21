"""
Config-change template store for the batch-config feature.

A small JSON-backed registry of reusable, named CLI snippets — the
operator saves a set of config commands once (per vendor) and re-applies
it to selected switches later. Mirrors ManualHostsStore: RLock-guarded,
atomic writes, mode 600.

File schema:
    {
      "templates": [
        {
          "name":        "enable-lldp",
          "vendor":      "cisco_ios",
          "description": "Turn on LLDP globally",
          "commands":    "lldp run",
          "added_by":    "mvieira",
          "created":     "2026-08-21T18:30:00"
        }, ...
      ]
    }
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

# Vendors we can push CLI config to (one vendor per batch). Keys match
# SwitchState.vendor / the VendorDetector output.
VALID_VENDORS: Tuple[str, ...] = ("aruba_cx", "cisco_ios", "arista_eos")


class ConfigTemplateStore:
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._lock = threading.RLock()
        self._templates: Dict[str, dict] = {}     # keyed by name
        self._load()

    # ─── persistence ─────────────────────────────────────────────────────────
    def _load(self) -> None:
        if not self._path.exists():
            log.info("Config templates: no store at %s — starting empty", self._path)
            return
        try:
            with self._path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            for t in data.get("templates", []):
                name = t.get("name")
                if not name or t.get("vendor") not in VALID_VENDORS:
                    continue
                self._templates[name] = t
            log.info("Config templates: loaded %d from %s",
                     len(self._templates), self._path)
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Config templates: could not read %s (%s) — starting empty",
                        self._path, exc)

    def _save(self) -> None:
        """Atomic save, mode 600. Caller already holds self._lock."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=".config-templates-", suffix=".tmp",
            dir=str(self._path.parent),
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                json.dump({"templates": list(self._templates.values())},
                          tmp, indent=2, sort_keys=True)
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

    # ─── access ──────────────────────────────────────────────────────────────
    def list_templates(self) -> List[dict]:
        with self._lock:
            return sorted((dict(t) for t in self._templates.values()),
                          key=lambda t: (t.get("vendor", ""), t.get("name", "")))

    def get(self, name: str) -> Optional[dict]:
        with self._lock:
            t = self._templates.get(name)
            return dict(t) if t else None

    def save_template(self, name: str, vendor: str, commands: str,
                      description: str = "", added_by: str = "") -> bool:
        """Create or update a template. Returns False on invalid input."""
        name = (name or "").strip()
        vendor = (vendor or "").strip()
        if not name or vendor not in VALID_VENDORS or not (commands or "").strip():
            return False
        with self._lock:
            existing = self._templates.get(name, {})
            self._templates[name] = {
                "name":        name,
                "vendor":      vendor,
                "description": (description or "").strip(),
                "commands":    commands,
                "added_by":    added_by or existing.get("added_by", ""),
                "created":     existing.get("created") or datetime.now().isoformat(timespec="seconds"),
                "updated":     datetime.now().isoformat(timespec="seconds"),
            }
            self._save()
        log.info("Config template saved: %s (%s)", name, vendor)
        return True

    def remove(self, name: str) -> bool:
        with self._lock:
            if name not in self._templates:
                return False
            del self._templates[name]
            self._save()
        log.info("Config template removed: %s", name)
        return True
