"""MongoDB backend for AgentState (data-layer Phase 1).

Implements the same snapshot-oriented ``Store`` contract as JsonStore, mapping
the payload onto two collections:

  * ``devices``  — one document per switch/controller, ``_id = name``.
  * ``runtime``  — a single ``_id="runtime"`` doc holding the non-device
                   singletons (backup result, scanner inventory + last run,
                   ARP last-run timestamps).

``load()`` reconstructs the exact snapshot dict AgentState expects, so the
hydration code in state.py is unchanged. ``save()`` upserts all devices in one
bulk write, deletes devices no longer present, and upserts the runtime doc.

Resilience: pymongo is imported lazily; a Mongo outage never crashes the agent
— load() returns None (start empty) and save() logs and no-ops, so monitoring
keeps running in memory and persistence resumes when Mongo returns. All values
in the payload are JSON-native (timestamps are already ISO strings), so they
store directly.
"""

from __future__ import annotations

import logging
from typing import Optional

log = logging.getLogger(__name__)

_RUNTIME_ID = "runtime"
_RUNTIME_KEYS = ("backup", "device_inventory", "scanner_last_run", "arp_last_run")


class MongoStore:
    def __init__(self, uri: str, db_name: str = "aruba_agent",
                 *, devices_collection: str = "devices",
                 runtime_collection: str = "runtime",
                 server_selection_timeout_ms: int = 5000,
                 tls: bool = False) -> None:
        self._uri = uri
        self._db_name = db_name
        self._devices_name = devices_collection
        self._runtime_name = runtime_collection
        self._client = None
        self._ReplaceOne = None
        self.error: str = ""

        try:
            from pymongo import MongoClient, ReplaceOne     # lazy
        except ImportError as exc:
            self.error = (f"pymongo not installed — pip3 install -r "
                          f"/opt/aruba-agent/requirements.txt ({exc})")
            log.error("MongoStore: %s", self.error)
            return

        self._ReplaceOne = ReplaceOne
        try:
            kwargs = {"serverSelectionTimeoutMS": server_selection_timeout_ms}
            if tls:
                kwargs["tls"] = True
            self._client = MongoClient(uri, **kwargs)
            # Fail-soft health check: warn (don't crash) if unreachable now.
            try:
                self._client.admin.command("ping")
                log.info("MongoStore: connected to %s db=%s", _redact_uri(uri), db_name)
            except Exception as exc:
                log.warning("MongoStore: Mongo not reachable yet at %s (%s) — "
                            "will retry on use", _redact_uri(uri), exc)
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            log.error("MongoStore: could not initialize client: %s", self.error)
            self._client = None

    # ── internals ────────────────────────────────────────────────────────────

    def _db(self):
        return None if self._client is None else self._client[self._db_name]

    # ── Store contract ─────────────────────────────────────────────────────────

    def load(self) -> Optional[dict]:
        db = self._db()
        if db is None:
            return None
        try:
            devices = []
            for doc in db[self._devices_name].find({}):
                doc.pop("_id", None)
                devices.append(doc)
            runtime = db[self._runtime_name].find_one({"_id": _RUNTIME_ID}) or {}
            runtime.pop("_id", None)
            if not devices and not runtime:
                return None
            payload = {"switches": devices}
            for k in _RUNTIME_KEYS:
                if k in runtime:
                    payload[k] = runtime[k]
            return payload
        except Exception as exc:
            log.error("MongoStore: load failed (%s) — starting empty", exc)
            return None

    def save(self, payload: dict) -> None:
        db = self._db()
        if db is None:
            log.warning("MongoStore: no connection — skipping save (state kept in memory)")
            return
        try:
            switches = payload.get("switches", []) or []
            names = [s["name"] for s in switches if s.get("name")]
            if switches:
                ops = [self._ReplaceOne({"_id": s["name"]},
                                        {**s, "_id": s["name"]}, upsert=True)
                       for s in switches if s.get("name")]
                if ops:
                    db[self._devices_name].bulk_write(ops, ordered=False)
            # Drop devices no longer present (propagate removals).
            db[self._devices_name].delete_many({"_id": {"$nin": names}})
            # Runtime singletons.
            runtime_doc = {"_id": _RUNTIME_ID}
            for k in _RUNTIME_KEYS:
                if k in payload:
                    runtime_doc[k] = payload[k]
            db[self._runtime_name].replace_one({"_id": _RUNTIME_ID},
                                               runtime_doc, upsert=True)
        except Exception as exc:
            log.error("MongoStore: save failed (%s) — state kept in memory", exc)

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None


def _redact_uri(uri: str) -> str:
    """Hide credentials in a mongodb:// URI for logging."""
    try:
        if "@" in uri and "://" in uri:
            scheme, rest = uri.split("://", 1)
            _creds, host = rest.split("@", 1)
            return f"{scheme}://***@{host}"
    except Exception:
        pass
    return uri
