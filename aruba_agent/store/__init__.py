"""
Pluggable persistence backends for AgentState (data-layer abstraction).

Phase 0 ships the JSON backend (identical to the historical state.json
behavior) behind a small ``Store`` interface, so a MongoStore (Phase 1) can
drop in without touching AgentState's public API or its ~19 call sites.
See DATA_LAYER_SPEC.md.
"""

from __future__ import annotations

from typing import Optional

from aruba_agent.store.base import Store


def make_store(backend: str = "json", *, snapshot_path: Optional[str] = None,
               cfg=None) -> Store:
    """Construct the configured Store. ``backend`` comes from [store] backend.

    - "json"  -> JsonStore(snapshot_path)  (default; current behavior)
    - "mongo" -> MongoStore  (Phase 1 — not yet implemented)
    """
    backend = (backend or "json").strip().lower()
    if backend == "json":
        from aruba_agent.store.json_store import JsonStore
        return JsonStore(snapshot_path)
    if backend == "mongo":
        from aruba_agent.store.mongo_store import MongoStore
        sec = cfg["store"] if (cfg is not None and cfg.has_section("store")) else {}
        return MongoStore(
            uri     = sec.get("uri", "mongodb://localhost:27017"),
            db_name = sec.get("db", "aruba_agent"),
            tls     = (sec.get("tls", "false") or "false").strip().lower() == "true",
            server_selection_timeout_ms = int(sec.get("server_timeout_ms", "5000") or "5000"),
            metrics_retention_days = int(sec.get("metrics_retention_days", "30") or "30"),
        )
    raise ValueError(f"unknown [store] backend: {backend!r}")
