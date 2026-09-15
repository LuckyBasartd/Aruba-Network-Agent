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
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

_RUNTIME_ID = "runtime"
_RUNTIME_KEYS = ("backup", "device_inventory", "scanner_last_run", "arp_last_run")


class MongoStore:
    def __init__(self, uri: str, db_name: str = "aruba_agent",
                 *, devices_collection: str = "devices",
                 runtime_collection: str = "runtime",
                 metrics_collection: str = "metrics",
                 counters_collection: str = "if_counters",
                 fdb_collection: str = "fdb",
                 server_selection_timeout_ms: int = 5000,
                 metrics_retention_days: int = 30,
                 tls: bool = False) -> None:
        self._uri = uri
        self._db_name = db_name
        self._devices_name = devices_collection
        self._runtime_name = runtime_collection
        self._metrics_name = metrics_collection
        self._counters_name = counters_collection
        self._fdb_name = fdb_collection
        self._fdb_indexed = False
        self._metrics_indexed = False
        self._metrics_retention_days = max(1, int(metrics_retention_days or 30))
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

    def healthy(self) -> bool:
        """True if Mongo answers a ping right now."""
        if self._client is None:
            return False
        try:
            self._client.admin.command("ping")
            return True
        except Exception:
            return False

    # ── time-series metrics (interface counters, RF, CPU, ...) ────────────────

    def _ensure_metrics_index(self, db) -> None:
        if self._metrics_indexed:
            return
        try:
            db[self._metrics_name].create_index([("device", 1), ("metric", 1), ("ts", 1)])
            # TTL: auto-expire samples so the time-series can't grow without
            # bound (a weekend of fleet polling is millions of docs). ts is a
            # BSON Date, so Mongo's background TTL monitor reaps old ones.
            db[self._metrics_name].create_index(
                "ts", expireAfterSeconds=self._metrics_retention_days * 86400,
                name="ts_ttl")
            self._metrics_indexed = True
        except Exception as exc:
            log.debug("MongoStore: metrics index create failed (%s)", exc)

    def record_metric(self, device: str, metric: str, value,
                      ts=None, labels: Optional[dict] = None) -> None:
        db = self._db()
        if db is None:
            return
        self._ensure_metrics_index(db)
        doc = {"ts": ts or datetime.now(timezone.utc),
               "device": device, "metric": metric, "value": value}
        if labels:
            doc["labels"] = labels
        try:
            db[self._metrics_name].insert_one(doc)
        except Exception as exc:
            log.error("MongoStore: record_metric failed (%s)", exc)

    def query_metrics(self, device: str, metric: str, start, end) -> list:
        db = self._db()
        if db is None:
            return []
        try:
            cur = db[self._metrics_name].find(
                {"device": device, "metric": metric,
                 "ts": {"$gte": start, "$lte": end}}).sort("ts", 1)
            out = []
            for d in cur:
                d.pop("_id", None)
                out.append(d)
            return out
        except Exception as exc:
            log.error("MongoStore: query_metrics failed (%s)", exc)
            return []

    # ── raw interface counter snapshots (for restart-safe utilization) ────────

    def save_counters(self, device: str, counters: dict, ts=None) -> None:
        """Upsert the latest {ifIndex: [ts, hc_in, hc_out]} snapshot for one
        device (one document, _id=device). Counters are stored as strings so a
        fully-wrapped Counter64 can't overflow BSON int64."""
        db = self._db()
        if db is None:
            return
        safe = {idx: [t, str(a), str(b)] for idx, (t, a, b) in
                ((k, (v[0], v[1], v[2])) for k, v in (counters or {}).items())}
        doc = {"_id": device, "ts": ts or datetime.now(timezone.utc),
               "counters": safe}
        try:
            db[self._counters_name].replace_one({"_id": device}, doc, upsert=True)
        except Exception as exc:
            log.error("MongoStore: save_counters failed for %s (%s)", device, exc)

    def load_counters(self, device: str) -> Optional[dict]:
        db = self._db()
        if db is None:
            return None
        try:
            doc = db[self._counters_name].find_one({"_id": device})
        except Exception as exc:
            log.error("MongoStore: load_counters failed for %s (%s)", device, exc)
            return None
        if not doc:
            return None
        return doc.get("counters") or {}

    # ── MAC forwarding database (bridge FDB) ──────────────────────────────────

    def _ensure_fdb_index(self, db) -> None:
        if self._fdb_indexed:
            return
        try:
            db[self._fdb_name].create_index("mac")
            db[self._fdb_name].create_index("device")
            self._fdb_indexed = True
        except Exception as exc:
            log.debug("MongoStore: fdb index create failed (%s)", exc)

    def save_fdb(self, device: str, records: list, ts=None) -> None:
        """Replace one device's FDB rows (one doc per learned MAC/port)."""
        db = self._db()
        if db is None:
            return
        when = ts or datetime.now(timezone.utc)
        try:
            self._ensure_fdb_index(db)
            coll = db[self._fdb_name]
            coll.delete_many({"device": device})
            docs = []
            for r in (records or []):
                docs.append({
                    "device": device, "mac": r.get("mac"),
                    "mac_fmt": r.get("mac_fmt"), "vlan": r.get("vlan"),
                    "ifindex": r.get("ifindex"), "ifname": r.get("ifname"),
                    "port_mac_count": r.get("port_mac_count"), "ts": when,
                })
            if docs:
                coll.insert_many(docs, ordered=False)
        except Exception as exc:
            log.error("MongoStore: save_fdb failed for %s (%s)", device, exc)

    def search_fdb(self, mac: str, limit: int = 200) -> list:
        db = self._db()
        if db is None:
            return []
        try:
            cur = (db[self._fdb_name].find({"mac": mac})
                   .sort("port_mac_count", 1).limit(int(limit)))
            out = []
            for d in cur:
                d.pop("_id", None)
                out.append(d)
            return out
        except Exception as exc:
            log.error("MongoStore: search_fdb failed (%s)", exc)
            return []

    def load_fdb(self, device: str) -> list:
        db = self._db()
        if db is None:
            return []
        try:
            cur = db[self._fdb_name].find({"device": device}).sort("ifindex", 1)
            out = []
            for d in cur:
                d.pop("_id", None)
                out.append(d)
            return out
        except Exception as exc:
            log.error("MongoStore: load_fdb failed (%s)", exc)
            return []

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
