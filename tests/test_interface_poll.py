"""InterfacePollTask — eligibility filtering + utilization across two polls."""
import configparser
from aruba_agent import interfaces as ifc
from aruba_agent.tasks import interface_poll as ip


class SW:
    def __init__(self, name, host, mode="auto", unmanaged=False, profile=""):
        self.name=name; self.host=host; self.monitor_mode=mode
        self.unmanaged=unmanaged; self.snmp_profile=profile

class State:
    def __init__(self, sws): self.switches={s.name: s for s in sws}

class FakeSnmp:
    def __init__(self): self.counters={"in":1000,"out":2000}; self.last_error=""
    def bulk_walk(self, host, bases, profile_name=None):
        m={
            ifc.OIDS["if_name"]:{"1":"1/1/1"}, ifc.OIDS["if_type"]:{"1":"6"},
            ifc.OIDS["oper"]:{"1":"1"}, ifc.OIDS["admin"]:{"1":"1"},
            ifc.OIDS["high_speed"]:{"1":"1000"},
            ifc.OIDS["hc_in"]:{"1":str(self.counters["in"])},
            ifc.OIDS["hc_out"]:{"1":str(self.counters["out"])},
        }
        return {b:m.get(b,{}) for b in bases}

class FakeStore:
    def __init__(self): self.metrics=[]
    def record_metric(self, device, metric, value, ts=None, labels=None):
        self.metrics.append((device, metric, value))

def _cfg(**over):
    c=configparser.ConfigParser(); c["interfaces"]={"enabled":"true","jitter_seconds":"0",**over}
    return c


def test_eligible_filters():
    st=State([SW("a","10.0.0.1"), SW("b","10.0.0.2",mode="icmp"),
              SW("c","10.0.0.3",unmanaged=True), SW("d","10.0.0.4")])
    t=ip.InterfacePollTask(_cfg(), st, FakeSnmp(), FakeStore())
    names={s.name for s in t.eligible()}
    assert names=={"a","d"}           # icmp + unmanaged excluded


def test_include_exclude():
    st=State([SW("core1","10.0.0.1"), SW("edge1","10.0.0.2"), SW("edge2","10.40.0.5")])
    t=ip.InterfacePollTask(_cfg(include="core1, 10.40.0.0/24"), st, FakeSnmp(), FakeStore())
    assert {s.name for s in t.eligible()}=={"core1","edge2"}   # by name + CIDR
    t2=ip.InterfacePollTask(_cfg(exclude="edge1"), st, FakeSnmp(), FakeStore())
    assert {s.name for s in t2.eligible()}=={"core1","edge2"}


def test_util_computed_on_second_poll(monkeypatch):
    st=State([SW("a","10.0.0.1")]); snmp=FakeSnmp(); store=FakeStore()
    t=ip.InterfacePollTask(_cfg(), st, snmp, store)
    clock={"t":1000.0}
    monkeypatch.setattr(ip.time, "time", lambda: clock["t"])
    # poll 1 — establishes baseline, no util yet
    t.run()
    assert store.metrics==[]
    cur=t.get_current("a"); assert cur and cur[0]["in_util"] is None
    # advance 60s; 450,000,000 bytes = 3.6 Gbit over 60s on a 1Gbps link = 6%
    clock["t"]=1060.0
    snmp.counters={"in":1000+450_000_000, "out":2000+450_000_000}
    t.run()
    got={m[1]:m[2] for m in store.metrics}
    assert "if.1.in_util" in got and "if.1.out_util" in got
    assert 5.9 <= got["if.1.in_util"] <= 6.1
    cur=t.get_current("a"); assert cur[0]["in_util"] is not None


def test_disabled_or_no_snmp_noop():
    st=State([SW("a","10.0.0.1")])
    ip.InterfacePollTask(_cfg(enabled="false"), st, FakeSnmp(), FakeStore()).run()  # no raise
    t=ip.InterfacePollTask(_cfg(), st, None, FakeStore()); t.run()                   # snmp None
    assert t.summary()=={}


class FakeStoreWithCounters(FakeStore):
    """FakeStore that also persists counter snapshots (like MongoStore), so we
    can prove utilization survives a simulated agent restart."""
    def __init__(self):
        super().__init__(); self._counters={}
    def save_counters(self, device, counters, ts=None):
        # emulate Mongo's string storage round-trip
        self._counters[device]={idx:[t,str(a),str(b)] for idx,(t,a,b) in counters.items()}
    def load_counters(self, device):
        return self._counters.get(device)


def test_util_survives_restart_via_store(monkeypatch):
    """Poll once, throw the task away (restart), build a fresh task against the
    same store: the second poll must still compute util from the persisted
    baseline — no in-memory _prev carried over."""
    st=State([SW("a","10.0.0.1")]); snmp=FakeSnmp(); store=FakeStoreWithCounters()
    clock={"t":1000.0}
    monkeypatch.setattr(ip.time, "time", lambda: clock["t"])

    t1=ip.InterfacePollTask(_cfg(), st, snmp, store)
    t1.run()
    assert store.metrics==[]                       # baseline only
    assert store._counters.get("a")                # counters persisted

    # ---- simulate restart: brand-new task, empty in-memory _prev ----
    clock["t"]=1060.0
    snmp.counters={"in":1000+450_000_000, "out":2000+450_000_000}
    t2=ip.InterfacePollTask(_cfg(), st, snmp, store)
    assert t2._prev=={}                            # cold start, nothing in memory
    t2.run()
    got={m[1]:m[2] for m in store.metrics}
    assert "if.1.in_util" in got and 5.9 <= got["if.1.in_util"] <= 6.1


def test_run_skips_when_previous_cycle_in_flight():
    """The overlap guard must drop a tick if a sweep is already running, so a
    slow full-fleet poll can't stack on itself."""
    st=State([SW("a","10.0.0.1")]); snmp=FakeSnmp(); store=FakeStore()
    t=ip.InterfacePollTask(_cfg(), st, snmp, store)
    assert t._running.acquire(blocking=False)      # simulate an in-flight sweep
    try:
        t.run()                                    # should no-op immediately
        assert store.metrics==[] and t.summary()=={}
    finally:
        t._running.release()
    # lock is free again -> a normal run proceeds
    t.run()
    assert t.get_current("a")                       # polled this time


class FakeSnmpZero:
    """Two polls: first baseline, second with ZERO traffic delta (idle port)."""
    last_error=""
    def __init__(self): self.counters={"in":1000,"out":2000}
    def bulk_walk(self, host, bases, profile_name=None):
        m={ifc.OIDS["if_name"]:{"1":"1/1/1"}, ifc.OIDS["if_type"]:{"1":"6"},
           ifc.OIDS["oper"]:{"1":"1"}, ifc.OIDS["admin"]:{"1":"1"},
           ifc.OIDS["high_speed"]:{"1":"1000"},
           ifc.OIDS["hc_in"]:{"1":str(self.counters["in"])},
           ifc.OIDS["hc_out"]:{"1":str(self.counters["out"])}}
        return {b:m.get(b,{}) for b in bases}


def test_zero_util_not_recorded_by_default(monkeypatch):
    st=State([SW("a","10.0.0.1")]); snmp=FakeSnmpZero(); store=FakeStore()
    t=ip.InterfacePollTask(_cfg(), st, snmp, store)   # record_zero_util defaults false
    clock={"t":1000.0}; monkeypatch.setattr(ip.time,"time",lambda: clock["t"])
    t.run()                       # baseline
    clock["t"]=1060.0             # no counter change -> util 0.0
    t.run()
    assert store.metrics==[]      # 0% not recorded


def test_zero_util_recorded_when_enabled(monkeypatch):
    st=State([SW("a","10.0.0.1")]); snmp=FakeSnmpZero(); store=FakeStore()
    t=ip.InterfacePollTask(_cfg(record_zero_util="true"), st, snmp, store)
    clock={"t":1000.0}; monkeypatch.setattr(ip.time,"time",lambda: clock["t"])
    t.run(); clock["t"]=1060.0; t.run()
    got={m[1] for m in store.metrics}
    assert "if.1.in_util" in got and "if.1.out_util" in got   # zeros recorded


def test_record_metrics_false_disables(monkeypatch):
    st=State([SW("a","10.0.0.1")]); snmp=FakeSnmp(); store=FakeStore()
    t=ip.InterfacePollTask(_cfg(record_metrics="false"), st, snmp, store)
    clock={"t":1000.0}; monkeypatch.setattr(ip.time,"time",lambda: clock["t"])
    t.run(); clock["t"]=1060.0
    snmp.counters={"in":1000+450_000_000,"out":2000+450_000_000}
    t.run()
    assert store.metrics==[]      # non-zero util still not recorded when off
    assert t.get_current("a")     # but the live table still populates
