"""Store backend contract tests (data-layer Phase 0)."""
import json
import pytest

from aruba_agent.store import make_store
from aruba_agent.store.json_store import JsonStore
from aruba_agent.store.base import Store


def test_jsonstore_roundtrip(tmp_path):
    p = tmp_path / "state.json"
    st = JsonStore(str(p))
    assert st.load() is None                      # nothing yet
    payload = {"switches": [{"name": "a", "host": "1.1.1.1"}], "backup": {}}
    st.save(payload)
    assert p.exists()
    assert st.load() == payload
    # written form is pretty-printed + sorted (byte-stable)
    text = p.read_text()
    assert json.loads(text) == payload
    assert '\n  "backup"' in text or '"backup"' in text


def test_jsonstore_ephemeral_none():
    st = JsonStore(None)
    assert st.load() is None
    st.save({"switches": []})                     # no-op, must not raise
    assert st.load() is None


def test_jsonstore_corrupt_file(tmp_path):
    p = tmp_path / "state.json"
    p.write_text("{ this is not json ")
    st = JsonStore(str(p))
    assert st.load() is None                       # tolerated, returns None


def test_jsonstore_atomic_overwrite(tmp_path):
    p = tmp_path / "state.json"
    st = JsonStore(str(p))
    st.save({"v": 1})
    st.save({"v": 2})
    assert st.load() == {"v": 2}
    # no leftover temp files
    assert [x.name for x in tmp_path.iterdir()] == ["state.json"]


def test_make_store_defaults_json(tmp_path):
    st = make_store("json", snapshot_path=str(tmp_path / "s.json"))
    assert isinstance(st, JsonStore)
    assert isinstance(st, Store)                    # satisfies the protocol


def test_make_store_mongo_not_yet():
    with pytest.raises(NotImplementedError):
        make_store("mongo", snapshot_path=None)


def test_make_store_unknown():
    with pytest.raises(ValueError):
        make_store("bogus")
