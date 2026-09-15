"""fdb.py — MAC normalization + bridge-FDB assembly (Q-BRIDGE + fallback)."""
from aruba_agent import fdb


def test_normalize_and_format_mac():
    for spelling in ["aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF",
                     "aabb.ccdd.eeff", "AABBCCDDEEFF"]:
        assert fdb.normalize_mac(spelling) == "aabbccddeeff"
    assert fdb.normalize_mac("nope") is None
    assert fdb.normalize_mac("") is None
    assert fdb.format_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"


def test_assemble_qbridge_maps_bridgeport_to_ifindex():
    # dot1qTpFdbPort: fdbid=10, mac 00:11:22:33:44:55 on bridge port 7
    cols = {
        fdb.OID_Q_FDB_PORT: {"10.0.17.34.51.68.85": "7"},
        fdb.OID_BASEPORT_IF: {"7": "107"},            # bridge port 7 -> ifIndex 107
        fdb.OID_IF_NAME:     {"107": "1/1/7"},
    }
    recs = fdb.assemble_fdb(cols)
    assert len(recs) == 1
    r = recs[0]
    assert r["mac"] == "001122334455" and r["mac_fmt"] == "00:11:22:33:44:55"
    assert r["vlan"] == 10 and r["ifindex"] == "107" and r["ifname"] == "1/1/7"
    assert r["port_mac_count"] == 1


def test_edge_vs_uplink_port_mac_count():
    # one access port (1 mac) + an uplink that learned 3 macs
    q = {
        "1.0.17.34.51.68.1":   "2",     # mac ..01 on port 2 (access)
        "1.0.17.34.51.68.10":  "9",     # ..0a on port 9 (uplink)
        "1.0.17.34.51.68.11":  "9",     # ..0b on port 9
        "1.0.17.34.51.68.12":  "9",     # ..0c on port 9
    }
    cols = {fdb.OID_Q_FDB_PORT: q,
            fdb.OID_BASEPORT_IF: {"2": "2", "9": "9"},
            fdb.OID_IF_NAME: {"2": "1/1/2", "9": "1/1/9"}}
    recs = {r["mac"]: r for r in fdb.assemble_fdb(cols)}
    assert recs["001122334401"]["port_mac_count"] == 1     # access/edge
    assert recs["00112233440a"]["port_mac_count"] == 3     # uplink/trunk


def test_fallback_to_dot1d_when_no_qbridge():
    cols = {
        fdb.OID_D_FDB_PORT: {"0.17.34.51.68.85": "3"},     # mac -> bridge port 3
        fdb.OID_BASEPORT_IF: {"3": "203"},
        fdb.OID_IF_NAME: {"203": "1/1/3"},
    }
    recs = fdb.assemble_fdb(cols)
    assert len(recs) == 1 and recs[0]["ifindex"] == "203" and recs[0]["vlan"] == 0


def test_port_zero_and_identity_fallback():
    # port 0 = not learned -> dropped; missing baseport map -> identity (port==ifindex)
    cols = {fdb.OID_Q_FDB_PORT: {"1.0.17.34.51.68.1": "0",
                                 "1.0.17.34.51.68.2": "5"},
            fdb.OID_IF_NAME: {"5": "1/1/5"}}
    recs = fdb.assemble_fdb(cols)
    assert len(recs) == 1 and recs[0]["ifindex"] == "5"      # identity fallback


def test_collect_snmp_failure_returns_none():
    class Dead:
        def bulk_walk(self, *a, **k): return None
    assert fdb.collect(Dead(), "x") is None
