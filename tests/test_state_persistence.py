"""AgentState persists/rehydrates through the Store abstraction (Phase 0).

Proves the refactor is behavior-preserving and that AgentState works against
any Store implementation (here an in-memory MemoryStore), which is what lets
MongoStore drop in later.
"""
from datetime import datetime

from aruba_agent.state import AgentState
from aruba_agent.store.json_store import JsonStore


class MemoryStore:
    """Minimal in-memory Store — proves AgentState is backend-agnostic."""
    def __init__(self):
        self.payload = None
        self.saves = 0
    def load(self):
        return self.payload
    def save(self, payload):
        self.saves += 1
        self.payload = payload
    def close(self):
        pass


def _populate(st: AgentState):
    st.register_switch("sw1", "10.0.0.1", monitor_mode="auto")
    st.pin_vendor("sw1", "aruba_aos8")
    st.update_switch("sw1", is_down=True, last_event="DOWN")
    st.set_alert_mute("sw1", True, None)
    st.set_backup_result(3, 1, [{"ip": "10.0.0.9", "hostname": "x", "issue": "auth"}])
    st.set_arp_last_run("bldgA")


def test_memorystore_roundtrip():
    store = MemoryStore()
    st = AgentState(store=store)
    _populate(st)
    assert store.saves > 0 and store.payload is not None

    # New AgentState on the same store rehydrates identically
    st2 = AgentState(store=store)
    assert "sw1" in st2.switches
    sw = st2.switches["sw1"]
    assert sw.host == "10.0.0.1" and sw.vendor == "aruba_aos8"
    assert sw.is_down is True and sw.alerts_muted is True
    assert st2.backup.success_count == 3 and st2.backup.failed_count == 1
    assert "bldgA" in st2.arp_last_run


def test_jsonstore_end_to_end(tmp_path):
    path = str(tmp_path / "state.json")
    st = AgentState(store=JsonStore(path))
    _populate(st)

    # Rehydrate from disk via a fresh JsonStore
    st2 = AgentState(store=JsonStore(path))
    d = st2.to_dict()
    names = [s["name"] for s in d["switches"]]
    assert names == ["sw1"]
    assert d["backup"]["success_count"] == 3


def test_snapshot_path_still_works(tmp_path):
    """Back-compat: constructing with snapshot_path builds a JsonStore."""
    path = str(tmp_path / "state.json")
    st = AgentState(snapshot_path=path)
    _populate(st)
    assert (tmp_path / "state.json").exists()
    st2 = AgentState(snapshot_path=path)
    assert "sw1" in st2.switches


def test_ephemeral_no_persistence():
    st = AgentState()                 # no path, no store -> JsonStore(None)
    _populate(st)                     # must not raise
    assert "sw1" in st.switches       # in-memory works
