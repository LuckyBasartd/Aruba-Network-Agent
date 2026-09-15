"""JSON file backend — the historical state.json persistence, extracted verbatim.

Atomic write: temp file in the same directory, fsync, then os.replace over the
target. A path of None makes the store ephemeral (load -> None, save -> no-op),
preserving AgentState's "no snapshot_path = in-memory only" behavior.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


class JsonStore:
    def __init__(self, path: Optional[str]) -> None:
        self.path: Optional[Path] = Path(path) if path else None

    def load(self) -> Optional[dict]:
        path = self.path
        if path is None or not path.exists():
            return None
        try:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("JsonStore: could not load %s (%s) — starting empty",
                        path, exc)
            return None

    def save(self, payload: dict) -> None:
        path = self.path
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(prefix=".state-", suffix=".tmp",
                                            dir=str(path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                    json.dump(payload, tmp, indent=2, sort_keys=True)
                    tmp.flush()
                    os.fsync(tmp.fileno())
                os.replace(tmp_name, path)
            except Exception:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
        except OSError as exc:
            log.warning("JsonStore: could not persist state to %s: %s", path, exc)

    # Time-series is not supported on the JSON backend (use [store] backend =
    # mongo for interface/RF/CPU history). These are safe no-ops so callers
    # don't need to branch on the backend.
    def record_metric(self, device, metric, value, ts=None, labels=None):
        return None

    def query_metrics(self, device, metric, start, end):
        return []

    # Interface counter snapshots are persisted only on the Mongo backend
    # (same rationale as the time-series no-ops above). On JSON the poll task
    # keeps counters in memory, so utilization simply needs a second poll after
    # a restart — no crash, no branch at the call site.
    def save_counters(self, device, counters, ts=None):
        return None

    def load_counters(self, device):
        return None

    # FDB (MAC table) is Mongo-only, like metrics/counters.
    def save_fdb(self, device, records, ts=None):
        return None

    def search_fdb(self, mac, limit=200):
        return []

    def load_fdb(self, device):
        return []

    def save_neighbors(self, device, records, ts=None):
        return None

    def load_neighbors(self, device):
        return []

    def close(self) -> None:
        pass
