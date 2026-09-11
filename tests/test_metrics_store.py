"""Store time-series metrics: MongoStore (fake pymongo) + JsonStore no-op."""
import sys, types
from datetime import datetime, timezone, timedelta

# ---- fake pymongo with a metrics-capable collection ----
class _Cursor:
    def __init__(self, docs): self._docs = docs
    def sort(self, field, direction=1):
        self._docs = sorted(self._docs, key=lambda d: d.get(field),
                            reverse=(direction == -1))
        return self
    def __iter__(self): return iter(self._docs)

class _Coll:
    def __init__(self): self.docs = []
    def insert_one(self, doc): self.docs.append(dict(doc))
    def find(self, q=None):
        q = q or {}
        out = []
        for d in self.docs:
            ok = True
            for k, v in q.items():
                if isinstance(v, dict) and ("$gte" in v or "$lte" in v):
                    dv = d.get(k)
                    if "$gte" in v and dv < v["$gte"]: ok = False
                    if "$lte" in v and dv > v["$lte"]: ok = False
                elif d.get(k) != v:
                    ok = False
            if ok: out.append(dict(d))
        return _Cursor(out)

class _DB:
    def __init__(self): self.colls = {}
    def __getitem__(self, n): return self.colls.setdefault(n, _Coll())

class _Admin:
    def command(self, *a, **k): return {"ok": 1}

class _Client:
    registry = {}
    def __init__(self, uri, **kw): self.uri = uri; self.admin = _Admin()
    def __getitem__(self, db): return _Client.registry.setdefault((self.uri, db), _DB())
    def close(self): pass

_fake = types.ModuleType("pymongo")
_fake.MongoClient = _Client
_fake.ReplaceOne = type("ReplaceOne", (), {"__init__": lambda s, f, d, upsert=False: None})
sys.modules["pymongo"] = _fake

from aruba_agent.store.mongo_store import MongoStore
from aruba_agent.store.json_store import JsonStore

URI = "mongodb://localhost:27017"


def test_mongo_record_and_query():
    _Client.registry.clear()
    st = MongoStore(URI, db_name="m1")
    assert st.healthy() is True
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(5):
        st.record_metric("sw1", "if.1.in_util", float(i * 10),
                         ts=base + timedelta(minutes=i), labels={"ifName": "1/1/1"})
    st.record_metric("sw1", "if.1.in_util", 999.0, ts=base - timedelta(days=2))  # out of range
    st.record_metric("sw2", "if.1.in_util", 1.0, ts=base)                        # other device
    rows = st.query_metrics("sw1", "if.1.in_util",
                            base, base + timedelta(minutes=10))
    assert [r["value"] for r in rows] == [0.0, 10.0, 20.0, 30.0, 40.0]  # sorted by ts
    assert rows[0]["labels"] == {"ifName": "1/1/1"}
    assert "_id" not in rows[0]


def test_mongo_metrics_outage_graceful():
    st = MongoStore(URI, db_name="m2")
    st._client = None                       # simulate down
    st.record_metric("x", "y", 1.0)         # no crash
    assert st.query_metrics("x", "y", 0, 1) == []
    assert st.healthy() is False


def test_jsonstore_metrics_are_noops(tmp_path):
    st = JsonStore(str(tmp_path / "s.json"))
    st.record_metric("sw1", "if.1.in_util", 5.0)   # no-op, no raise
    assert st.query_metrics("sw1", "if.1.in_util", 0, 1) == []
