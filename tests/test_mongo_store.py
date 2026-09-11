"""MongoStore tests (data-layer Phase 1) using an in-memory fake pymongo.

No real Mongo / driver needed: we inject a minimal fake `pymongo` that
persists per (uri, db) so reconnects see prior writes.
"""
import sys, types

# ---- fake pymongo (module-level so mongo_store's lazy import picks it up) ----
class _ReplaceOne:
    def __init__(self, filt, doc, upsert=False):
        self.filt, self.doc, self.upsert = filt, doc, upsert
    def apply(self, coll):
        coll.docs[self.filt["_id"]] = dict(self.doc)

class _Coll:
    def __init__(self): self.docs = {}
    def find(self, q=None): return [dict(d) for d in self.docs.values()]
    def find_one(self, q):
        d = self.docs.get(q.get("_id"))
        return dict(d) if d else None
    def bulk_write(self, ops, ordered=False):
        for op in ops: op.apply(self)
    def delete_many(self, q):
        cond = q.get("_id")
        if isinstance(cond, dict) and "$nin" in cond:
            keep = set(cond["$nin"])
            for k in list(self.docs):
                if k not in keep: del self.docs[k]
    def replace_one(self, q, doc, upsert=False):
        self.docs[q["_id"]] = dict(doc)

class _DB:
    def __init__(self): self.colls = {}
    def __getitem__(self, name): return self.colls.setdefault(name, _Coll())

class _Admin:
    def command(self, *a, **k): return {"ok": 1}

class _Client:
    registry = {}                       # (uri, db) -> _DB  (survives reconnect)
    raise_on_init = False
    def __init__(self, uri, **kw):
        if _Client.raise_on_init:
            raise RuntimeError("simulated connection failure")
        self.uri = uri; self.admin = _Admin()
    def __getitem__(self, dbname):
        return _Client.registry.setdefault((self.uri, dbname), _DB())
    def close(self): pass

_fake = types.ModuleType("pymongo")
_fake.MongoClient = _Client
_fake.ReplaceOne = _ReplaceOne
sys.modules["pymongo"] = _fake


def setup_function(func):
    # pytest runs all test modules in one process; another module may have
    # overwritten sys.modules["pymongo"] with its own fake. Re-assert ours
    # before each test so the right fake (with the methods this file needs)
    # is active regardless of collection/run order.
    sys.modules["pymongo"] = _fake

from aruba_agent.store.mongo_store import MongoStore, _redact_uri
from aruba_agent.state import AgentState

URI = "mongodb://localhost:27017"


def _fresh(dbname):
    _Client.registry.pop((URI, dbname), None)
    return MongoStore(URI, db_name=dbname)


def test_roundtrip_and_payload_shape():
    st = _fresh("t1")
    assert st.load() is None                        # empty
    payload = {
        "switches": [{"name": "sw1", "host": "10.0.0.1", "vendor": "aruba_cx",
                      "is_down": False}],
        "backup": {"timestamp": "2026-01-01T00:00:00", "success_count": 2,
                   "failed_count": 0, "failed_devices": []},
        "device_inventory": [{"ip": "10.0.0.1", "name": "sw1"}],
        "scanner_last_run": "2026-01-01T00:00:00",
        "arp_last_run": {"bldgA": "2026-01-01T00:00:00"},
    }
    st.save(payload)
    back = st.load()
    assert back["switches"][0]["name"] == "sw1"
    assert back["backup"]["success_count"] == 2
    assert back["device_inventory"] == [{"ip": "10.0.0.1", "name": "sw1"}]
    assert back["arp_last_run"] == {"bldgA": "2026-01-01T00:00:00"}
    assert "_id" not in back["switches"][0]          # _id stripped on load


def test_deletion_propagates():
    st = _fresh("t2")
    st.save({"switches": [{"name": "a", "host": "1"}, {"name": "b", "host": "2"}]})
    assert {s["name"] for s in st.load()["switches"]} == {"a", "b"}
    st.save({"switches": [{"name": "a", "host": "1"}]})   # b removed
    assert {s["name"] for s in st.load()["switches"]} == {"a"}


def test_outage_is_graceful():
    _Client.raise_on_init = True
    try:
        st = MongoStore(URI, db_name="t3")
        assert st._client is None
        assert st.load() is None                      # no crash
        st.save({"switches": [{"name": "x", "host": "1"}]})   # no-op, no crash
    finally:
        _Client.raise_on_init = False


def test_agentstate_through_mongostore():
    _Client.registry.pop((URI, "t4"), None)
    st = AgentState(store=MongoStore(URI, db_name="t4"))
    st.register_switch("sw1", "10.0.0.1", monitor_mode="auto")
    st.pin_vendor("sw1", "aruba_aos8")
    st.update_switch("sw1", is_down=True)
    st.set_backup_result(1, 0, [])
    # Rehydrate through a fresh MongoStore on the same db
    st2 = AgentState(store=MongoStore(URI, db_name="t4"))
    assert "sw1" in st2.switches
    assert st2.switches["sw1"].vendor == "aruba_aos8"
    assert st2.switches["sw1"].is_down is True
    assert st2.backup.success_count == 1


def test_redact_uri():
    assert _redact_uri("mongodb://user:secret@host:27017/db") == "mongodb://***@host:27017/db"
    assert _redact_uri("mongodb://host:27017") == "mongodb://host:27017"
