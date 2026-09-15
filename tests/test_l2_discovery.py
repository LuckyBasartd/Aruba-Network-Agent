"""L2DiscoveryTask — eligibility, FDB save, and edge-only MAC search."""
import configparser
from aruba_agent import fdb
from aruba_agent.tasks import l2_discovery as l2


class SW:
    def __init__(self, name, host, mode="auto", unmanaged=False, profile=""):
        self.name=name; self.host=host; self.monitor_mode=mode
        self.unmanaged=unmanaged; self.snmp_profile=profile

class State:
    def __init__(self, sws): self.switches={s.name: s for s in sws}

class FakeSnmp:
    """Returns a Q-BRIDGE FDB: mac ..01 on access port 2, and three macs on
    uplink port 9."""
    last_error=""
    def bulk_walk(self, host, bases, profile_name=None):
        q={"1.0.17.34.51.68.1":"2",
           "1.0.17.34.51.68.10":"9","1.0.17.34.51.68.11":"9","1.0.17.34.51.68.12":"9"}
        from aruba_agent import lldp
        m={fdb.OID_Q_FDB_PORT:q,
           fdb.OID_BASEPORT_IF:{"2":"2","9":"9"},
           fdb.OID_IF_NAME:{"2":"1/1/2","9":"1/1/9"},
           lldp.OID_LLDP_LOC_PORTID:{"2":"1/1/2"},
           lldp.OID_LLDP_REM_SYSNAME:{"0.2.1":"AP-lobby"},
           lldp.OID_LLDP_REM_CAP_ENA:{"0.2.1":"0x1000"}}
        return {b:m.get(b,{}) for b in bases}

class FakeFdbStore:
    def __init__(self): self.rows={}; self.neigh={}   # device -> [records]
    def save_fdb(self, device, records, ts=None): self.rows[device]=list(records)
    def save_neighbors(self, device, records, ts=None): self.neigh[device]=list(records)
    def load_neighbors(self, device): return self.neigh.get(device, [])
    def search_fdb(self, mac, limit=200):
        out=[]
        for dev, recs in self.rows.items():
            for r in recs:
                if r["mac"]==mac:
                    out.append({**r, "device":dev})
        return sorted(out, key=lambda r:r["port_mac_count"])[:limit]

def _cfg(**over):
    c=configparser.ConfigParser(); c["l2"]={"enabled":"true","jitter_seconds":"0",**over}
    return c


def test_poll_seconds_floor_and_default():
    assert l2.L2DiscoveryTask(_cfg(), State([]), FakeSnmp(), FakeFdbStore()).poll_seconds==3600
    assert l2.L2DiscoveryTask(_cfg(poll_seconds="60"), State([]), FakeSnmp(), FakeFdbStore()).poll_seconds==300


def test_eligible_filters():
    st=State([SW("a","10.0.0.1"), SW("b","10.0.0.2",mode="icmp"),
              SW("c","10.0.0.3",unmanaged=True)])
    t=l2.L2DiscoveryTask(_cfg(), st, FakeSnmp(), FakeFdbStore())
    assert {s.name for s in t.eligible()}=={"a"}


def test_run_saves_fdb_and_search_edge_only():
    st=State([SW("sw1","10.0.0.1")]); store=FakeFdbStore()
    t=l2.L2DiscoveryTask(_cfg(), st, FakeSnmp(), store)
    t.run()
    assert store.rows["sw1"]                       # FDB persisted
    assert t.summary()=={"sw1":4}
    # neighbors collected + classified
    assert store.neigh["sw1"] and store.neigh["sw1"][0]["device_type"]=="wireless-ap"
    assert t.neighbor_summary()=={"sw1":1}

    # edge-only search for the access-port mac -> single hit, count 1
    hits=t.search("00:11:22:33:44:01")
    assert len(hits)==1 and hits[0]["ifname"]=="1/1/2" and hits[0]["port_mac_count"]==1

    # an uplink mac: only one device learns it here, edge-only returns its best
    hits2=t.search("001122334 40a".replace(" ",""))
    assert hits2 and hits2[0]["ifname"]=="1/1/9"


def test_search_all_vs_edge():
    st=State([SW("sw1","10.0.0.1"), SW("sw2","10.0.0.2")]); store=FakeFdbStore()
    t=l2.L2DiscoveryTask(_cfg(), st, FakeSnmp(), store)
    t.run()   # both switches learn the same macs (same FakeSnmp)
    mac="00:11:22:33:44:01"
    assert len(t.search(mac, edge_only=False))==2      # both devices
    assert len(t.search(mac, edge_only=True))==2       # one best per device


def test_bad_mac_returns_empty():
    t=l2.L2DiscoveryTask(_cfg(), State([]), FakeSnmp(), FakeFdbStore())
    assert t.search("not-a-mac")==[]


def test_overlap_guard_skips():
    st=State([SW("a","10.0.0.1")]); t=l2.L2DiscoveryTask(_cfg(), st, FakeSnmp(), FakeFdbStore())
    assert t._running.acquire(blocking=False)
    try:
        t.run(); assert t.summary()=={}
    finally:
        t._running.release()
    t.run(); assert t.summary()=={"a":4}
