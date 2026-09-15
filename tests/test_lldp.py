"""lldp.py — capability classification + LLDP/CDP neighbor assembly."""
from aruba_agent import lldp


def test_classify_lldp_capability_bits():
    assert lldp.classify_lldp("0x1000") == "wireless-ap"   # bit 3
    assert lldp.classify_lldp("0x0400") == "voip-phone"    # bit 5
    assert lldp.classify_lldp("0x2000") == "switch"        # bit 2
    assert lldp.classify_lldp("0x0800") == "router"        # bit 4
    assert lldp.classify_lldp("0x0100") == "host"          # bit 7
    # phone that also advertises bridge -> phone wins (checked before bridge)
    assert lldp.classify_lldp("0x2400") == "voip-phone"
    assert lldp.classify_lldp("") == "unknown"


def test_classify_cdp_bitmask():
    assert lldp.classify_cdp("0x00000008") == "switch"
    assert lldp.classify_cdp("0x00000080") == "voip-phone"
    assert lldp.classify_cdp("0x00000001") == "router"
    assert lldp.classify_cdp("0x00000010") == "host"
    assert lldp.classify_cdp("41") == "router"             # decimal string, 0x29 has router bit


def test_assemble_lldp_maps_local_port_and_classifies():
    cols = {
        lldp.OID_LLDP_LOC_PORTID: {"5": "1/1/5", "9": "1/1/9"},
        # rem table suffix = timemark.localportnum.remindex
        lldp.OID_LLDP_REM_SYSNAME: {"0.5.1": "AP-315-lobby", "0.9.1": "phone-204"},
        lldp.OID_LLDP_REM_PORTID:  {"0.5.1": "eth0", "0.9.1": "1"},
        lldp.OID_LLDP_REM_SYSDESC: {"0.5.1": "ArubaOS AP", "0.9.1": "Polycom"},
        lldp.OID_LLDP_REM_CAP_ENA: {"0.5.1": "0x1000", "0.9.1": "0x2400"},
    }
    recs = {r["ifname"]: r for r in lldp.assemble_lldp(cols)}
    assert recs["1/1/5"]["neighbor"] == "AP-315-lobby"
    assert recs["1/1/5"]["device_type"] == "wireless-ap"
    assert recs["1/1/9"]["neighbor"] == "phone-204"
    assert recs["1/1/9"]["device_type"] == "voip-phone"
    assert recs["1/1/5"]["protocol"] == "lldp"


def test_assemble_cdp_uses_ifindex():
    cols = {
        lldp.OID_IF_NAME:      {"107": "1/1/7"},
        lldp.OID_CDP_DEVICEID: {"107.3": "SEP001122334455"},
        lldp.OID_CDP_DEVPORT:  {"107.3": "Port 1"},
        lldp.OID_CDP_PLATFORM: {"107.3": "Cisco IP Phone 7960"},
        lldp.OID_CDP_CAPS:     {"107.3": "0x00000090"},   # host+phone
    }
    recs = lldp.assemble_cdp(cols)
    assert len(recs) == 1
    assert recs[0]["ifname"] == "1/1/7" and recs[0]["protocol"] == "cdp"
    assert recs[0]["device_type"] == "voip-phone"


def test_assemble_prefers_lldp_over_cdp_on_same_port():
    cols = {
        lldp.OID_LLDP_LOC_PORTID:  {"7": "1/1/7"},
        lldp.OID_LLDP_REM_SYSNAME: {"0.7.1": "sw-neighbor"},
        lldp.OID_LLDP_REM_CAP_ENA: {"0.7.1": "0x2000"},
        lldp.OID_IF_NAME:          {"107": "1/1/7"},
        lldp.OID_CDP_DEVICEID:     {"107.3": "should-be-ignored"},
        lldp.OID_CDP_CAPS:         {"107.3": "0x00000008"},
    }
    recs = lldp.assemble(cols)
    by_if = {r["ifname"]: r for r in recs}
    assert by_if["1/1/7"]["protocol"] == "lldp"        # LLDP wins
    assert len(recs) == 1


def test_collect_snmp_failure_returns_none():
    class Dead:
        def bulk_walk(self, *a, **k): return None
    assert lldp.collect(Dead(), "x") is None
