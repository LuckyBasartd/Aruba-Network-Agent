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
        raise NotImplementedError(
            "MongoStore lands in Phase 1 of the data-layer migration "
            "(see DATA_LAYER_SPEC.md). Set [store] backend = json for now."
        )
    raise ValueError(f"unknown [store] backend: {backend!r}")
