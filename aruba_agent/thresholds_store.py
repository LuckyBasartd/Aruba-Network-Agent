"""
Threshold rule store for the alerting engine.

A JSON-backed registry of alert rules (RLock-guarded, atomic writes, mode 600 —
same shape as ConfigTemplateStore). Each rule watches one metric and fires when
the value crosses a threshold for a sustained duration.

File schema:
    {
      "rules": [
        {
          "name":       "Uplink in-util high",
          "enabled":    true,
          "metric":     "if_util_in",      # see VALID_METRICS
          "operator":   ">",               # see VALID_OPERATORS
          "value":      90.0,
          "duration_s": 300,               # sustained breach before alerting
          "severity":   "warning",         # warning | critical
          "include":    "10.40.0.0/24",    # scope CSV (names/IPs/CIDRs); ""=all
          "exclude":    "",
          "added_by":   "mvieira",
          "created":    "2026-09-16T09:00:00",
          "updated":    "2026-09-16T09:00:00"
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

# metric keys the evaluator understands (interface + device health)
VALID_METRICS: Tuple[str, ...] = (
    "if_util_in", "if_util_out", "crc_errors",
    "cpu", "memory", "temperature",
)
VALID_OPERATORS: Tuple[str, ...] = (">", ">=", "<", "<=")
VALID_SEVERITY: Tuple[str, ...] = ("warning", "critical")


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


class ThresholdStore:
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._lock = threading.RLock()
        self._rules: Dict[str, dict] = {}     # keyed by name
        self._load()

    # ─── persistence ─────────────────────────────────────────────────────────
    def _load(self) -> None:
        if not self._path.exists():
            log.info("Thresholds: no store at %s — starting empty", self._path)
            return
        try:
            with self._path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            for r in data.get("rules", []):
                name = (r.get("name") or "").strip()
                if name and self._valid(r):
                    self._rules[name] = r
            log.info("Thresholds: loaded %d rule(s) from %s",
                     len(self._rules), self._path)
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Thresholds: could not read %s (%s) — starting empty",
                        self._path, exc)

    @staticmethod
    def _valid(r: dict) -> bool:
        return (r.get("metric") in VALID_METRICS
                and r.get("operator") in VALID_OPERATORS
                and _num(r.get("value")) is not None
                and (r.get("severity") in VALID_SEVERITY))

    def _save(self) -> None:
        """Atomic save, mode 600. Caller already holds self._lock."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".thresholds-", suffix=".tmp",
                                        dir=str(self._path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                json.dump({"rules": list(self._rules.values())},
                          tmp, indent=2, sort_keys=True)
                tmp.flush(); os.fsync(tmp.fileno())
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
    def list_rules(self, enabled_only: bool = False) -> List[dict]:
        with self._lock:
            rs = [dict(r) for r in self._rules.values()]
        if enabled_only:
            rs = [r for r in rs if r.get("enabled", True)]
        return sorted(rs, key=lambda r: (r.get("metric", ""), r.get("name", "")))

    def get(self, name: str) -> Optional[dict]:
        with self._lock:
            r = self._rules.get(name)
            return dict(r) if r else None

    def save_rule(self, name: str, metric: str, operator: str, value,
                  duration_s=300, severity: str = "warning",
                  include: str = "", exclude: str = "",
                  enabled: bool = True, added_by: str = "") -> Tuple[bool, str]:
        """Create/update a rule. Returns (ok, error_message)."""
        name = (name or "").strip()
        metric = (metric or "").strip()
        operator = (operator or "").strip()
        severity = (severity or "warning").strip()
        if not name:
            return False, "name is required"
        if metric not in VALID_METRICS:
            return False, f"metric must be one of {', '.join(VALID_METRICS)}"
        if operator not in VALID_OPERATORS:
            return False, f"operator must be one of {', '.join(VALID_OPERATORS)}"
        if _num(value) is None:
            return False, "value must be a number"
        if severity not in VALID_SEVERITY:
            return False, "severity must be warning or critical"
        try:
            dur = max(0, int(duration_s))
        except (TypeError, ValueError):
            return False, "duration_s must be an integer"
        with self._lock:
            existing = self._rules.get(name, {})
            self._rules[name] = {
                "name": name, "enabled": bool(enabled),
                "metric": metric, "operator": operator, "value": _num(value),
                "duration_s": dur, "severity": severity,
                "include": (include or "").strip(), "exclude": (exclude or "").strip(),
                "added_by": added_by or existing.get("added_by", ""),
                "created": existing.get("created") or datetime.now().isoformat(timespec="seconds"),
                "updated": datetime.now().isoformat(timespec="seconds"),
            }
            self._save()
        log.info("Threshold rule saved: %s (%s %s %s)", name, metric, operator, value)
        return True, ""

    def set_enabled(self, name: str, enabled: bool) -> bool:
        with self._lock:
            r = self._rules.get(name)
            if not r:
                return False
            r["enabled"] = bool(enabled)
            r["updated"] = datetime.now().isoformat(timespec="seconds")
            self._save()
        return True

    def remove(self, name: str) -> bool:
        with self._lock:
            if name not in self._rules:
                return False
            del self._rules[name]
            self._save()
        log.info("Threshold rule removed: %s", name)
        return True
