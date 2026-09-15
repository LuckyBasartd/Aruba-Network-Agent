"""interfaces.py collector — pure assemble/filter/utilization + collect()."""
from aruba_agent import interfaces as ifc


def test_assemble_rows_physical_filter():
    cols = {
        "if_name":  {"1": "1/1/1", "2": "vlan10"},
        "if_type":  {"1": "6",      "2": "53"},     # 6=ethernet, 53=propVirtual
        "oper":     {"1": "1",      "2": "1"},
        "admin":    {"1": "1",      "2": "1"},
        "high_speed":{"1": "1000",  "2": "0"},
        "hc_in":    {"1": "1000",   "2": "5"},
        "hc_out":   {"1": "2000",   "2": "5"},
    }
    rows = ifc.assemble_rows(cols, physical_only=True)
    assert set(rows.keys()) == {"1"}                 # vlan10 filtered out
    r = rows["1"]
    assert r["name"] == "1/1/1" and r["oper"] == "up" and r["speed_mbps"] == 1000
    # physical_only=False keeps both
    assert set(ifc.assemble_rows(cols, physical_only=False).keys()) == {"1", "2"}


def test_oper_admin_mapping():
    cols = {"if_name": {"1": "p1"}, "if_type": {"1": "6"},
            "oper": {"1": "2"}, "admin": {"1": "2"}}
    r = ifc.assemble_rows(cols)["1"]
    assert r["oper"] == "down" and r["admin"] == "down"


def test_compute_util():
    # 1 Gbps, 60s, 100,000,000 bytes delta = 800,000,000 bits;
    # capacity = 1e9*60 = 6e10 -> ~1.33%
    u = ifc.compute_util(0, 100_000_000, 60, 1000)
    assert 1.3 <= u <= 1.34
    # full line rate clamps to 100
    assert ifc.compute_util(0, 1000*1_000_000//8*60, 60, 1000) == 100.0
    # first sample / no prev
    assert ifc.compute_util(None, 100, 60, 1000) is None
    # counter wrap (delta < 0)
    assert ifc.compute_util(500, 100, 60, 1000) is None
    # no speed / no elapsed
    assert ifc.compute_util(0, 100, 60, 0) is None
    assert ifc.compute_util(0, 100, 0, 1000) is None


def test_collect_with_mock_snmp():
    class FakeSnmp:
        def bulk_walk(self, host, bases, profile_name=None):
            # return {base: {ifIndex: value}} for the requested bases
            m = {
                ifc.OIDS["if_name"]: {"10": "1/1/1"},
                ifc.OIDS["if_type"]: {"10": "6"},
                ifc.OIDS["oper"]:    {"10": "1"},
                ifc.OIDS["admin"]:   {"10": "1"},
                ifc.OIDS["high_speed"]: {"10": "10000"},
                ifc.OIDS["hc_in"]:   {"10": "12345"},
                ifc.OIDS["hc_out"]:  {"10": "67890"},
            }
            return {b: m.get(b, {}) for b in bases}
    rows = ifc.collect(FakeSnmp(), "10.0.0.1", physical_only=True)
    assert list(rows.keys()) == ["10"]
    assert rows["10"]["name"] == "1/1/1" and rows["10"]["speed_mbps"] == 10000
    assert rows["10"]["hc_in"] == 12345


def test_collect_snmp_failure_returns_none():
    class DeadSnmp:
        def bulk_walk(self, *a, **k): return None
    assert ifc.collect(DeadSnmp(), "x") is None


def test_crc_err_from_fcs_not_iferrors():
    """CRC column must come from dot3StatsFCSErrors, independent of ifInErrors.
    WAP jumbo-frame negotiation bumps ifInErrors (giants) but not FCS, so a
    healthy AP port shows in_err>0 while crc_err==0."""
    cols = {
        "if_name": {"1": "1/1/1"}, "if_type": {"1": "6"},
        "oper": {"1": "1"}, "admin": {"1": "1"}, "high_speed": {"1": "5000"},
        "in_err":  {"1": "93440"},        # giants from AP jumbo negotiation
        "fcs_err": {"1": "0"},            # no real CRC errors
    }
    r = ifc.assemble_rows(cols)["1"]
    assert r["in_err"] == 93440 and r["crc_err"] == 0
    # a port with genuine CRC errors surfaces them
    cols["fcs_err"] = {"1": "17"}
    assert ifc.assemble_rows(cols)["1"]["crc_err"] == 17
