"""Store interface — the persistence contract AgentState depends on.

Snapshot-oriented for Phase 0: AgentState still owns the model<->dict
serialization; the Store only persists/loads that dict. This keeps the JSON
backend byte-identical to the historical state.json and lets a MongoStore map
the same payload onto collections in Phase 1 (with per-document upserts as a
later optimization).
"""

from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class Store(Protocol):
    def load(self) -> Optional[dict]:
        """Return the persisted snapshot dict, or None if nothing is stored."""
        ...

    def save(self, payload: dict) -> None:
        """Persist the snapshot dict. Must be durable/atomic per backend."""
        ...

    def close(self) -> None:
        """Release resources (no-op for file-based backends)."""
        ...

    def record_metric(self, device: str, metric: str, value,
                      ts=None, labels: "Optional[dict]" = None) -> None:
        """Append a time-series sample. No-op on backends without a TSDB."""
        ...

    def query_metrics(self, device: str, metric: str, start, end) -> list:
        """Return time-series samples [{ts, device, metric, value, labels}]."""
        ...

    def save_counters(self, device: str, counters: dict, ts=None) -> None:
        """Persist the latest raw interface counter snapshot for one device so
        utilization can be computed against it after an agent restart. counters
        is {ifIndex: [ts, hc_in, hc_out]}. No-op on backends without support."""
        ...

    def load_counters(self, device: str) -> "Optional[dict]":
        """Return the last persisted counter snapshot for one device, or None.
        No-op (None) on backends without support."""
        ...
