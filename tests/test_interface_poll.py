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
