"""health.py pure helpers + collect() with a fake SNMP; HealthPollTask samples."""
import configparser
from aruba_agent import health
from aruba_agent.tasks import health_poll as hp


def test_compute_mem_pct():
    assert health.compute_mem_pct(50, 200) == 25.0
    assert health.compute_mem_pct(0, 100) == 0.0
    assert health.compute_mem_pct(150, 100) == 100.0     # clamps
    assert health.compute_mem_pct(10, 0) is None
    assert health.compute_mem_pct("x", 100) is None


def test_average_and_max_temp():
    assert health.average(["10", "20", "30"]) == 20.0
    assert health.average([]) is None
    assert health.max_temp(["40", "55", "48"]) == 55.0
    assert health.max_temp([]) is None


class FakeSnmp:
    """ProCurve-style: cpu_get + mem_total/alloc scalars, temp walk."""
    def __init__(self): self.last_error = ""
    def get(self, host, oid, profile_name=None):
        m = {
            "1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0": "37",                 # cpu 37%
            "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5.1": "1000",         # mem total
            "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7.1": "400",          # mem alloc
        }
        return m.get(oid)
    def bulk_walk(self, host, oids, profile_name=None):
        return {health.OID_ENTPHYSENSOR_VAL: {"1": "41", "2": "53"}}


def test_collect_procurve_vendor():
    r = health.collect(FakeSnmp(), "10.0.0.1", vendor="aruba_os")
    assert r["cpu"] == 37.0
    assert r["memory"] == 40.0            # 400/1000
    assert r["temperature"] == 53.0       # max sensor


class FakeSnmpCX:
    """Aruba CX-style: hrProcessorLoad walk + entPhySensor temp; no vendor mem."""
    last_error = ""
    def get(self, host, oid, profile_name=None): return None
    def bulk_walk(self, host, oids, profile_name=None):
        out = {}
        if health.OID_HR_PROCESSOR_LOAD in oids:
            out[health.OID_HR_PROCESSOR_LOAD] = {"1": "20", "2": "40"}   # avg 30
        if health.OID_ENTPHYSENSOR_VAL in oids:
            out[health.OID_ENTPHYSENSOR_VAL] = {"1": "45"}
        # hrStorage RAM row for memory fallback
        if "1.3.6.1.2.1.25.2.3.1.5" in oids:
            out["1.3.6.1.2.1.25.2.3.1.2"] = {"3": "1.3.6.1.2.1.25.2.1.2"}  # RAM type
            out["1.3.6.1.2.1.25.2.3.1.5"] = {"3": "800"}
            out["1.3.6.1.2.1.25.2.3.1.6"] = {"3": "200"}
        return out


def test_collect_aruba_cx_fallbacks():
    r = health.collect(FakeSnmpCX(), "10.0.0.2", vendor="aruba_cx")
    assert r["cpu"] == 30.0
    assert r["temperature"] == 45.0
    assert r["memory"] == 25.0            # 200/800 via hrStorage RAM row


def test_collect_never_raises_on_dead_snmp():
    class Dead:
        def get(self, *a, **k): raise RuntimeError("x")
        def bulk_walk(self, *a, **k): raise RuntimeError("x")
    r = health.collect(Dead(), "10.0.0.9", vendor="cisco_ios")
    assert r == {"cpu": None, "memory": None, "temperature": None}


class SW:
    def __init__(s, name, host, vendor="aruba_os"): s.name=name; s.host=host; s.vendor=vendor; s.monitor_mode="auto"; s.unmanaged=False; s.snmp_profile=""
class State:
    def __init__(s, sws): s.switches={x.name:x for x in sws}
class FakeStore:
    def __init__(s): s.metrics=[]
    def record_metric(s, d, m, v, ts=None, labels=None): s.metrics.append((d,m,v))

def _cfg(**o):
    c=configparser.ConfigParser(); c["health"]={"enabled":"true","jitter_seconds":"0",**o}; return c


def test_health_task_records_and_samples():
    st=State([SW("sw1","10.0.0.1")]); store=FakeStore()
    t=hp.HealthPollTask(_cfg(), st, FakeSnmp(), store)
    t.run()
    got={m[1] for m in store.metrics}
    assert {"health.cpu","health.memory","health.temperature"} <= got
    samples={(s["metric"]) : s for s in t.samples()}
    assert samples["cpu"]["value"]==37.0 and samples["cpu"]["device"]=="sw1"
    assert samples["memory"]["instance"]==""
