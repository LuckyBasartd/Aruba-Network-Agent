"""
Layer-2 forwarding database (bridge MAC table) collector.

Pure, testable core: turns SNMP walks of the bridge MIBs into per-port MAC
records, so we can answer "which switch/port is this MAC on?". SNMP I/O is a
single `snmp.bulk_walk` (see snmp.py); everything else here is pure Python.

MIBs walked (in priority order):
  * Q-BRIDGE dot1qTpFdbPort (1.3.6.1.2.1.17.7.1.2.2.1.2)
        index = dot1qFdbId . mac(6 octets)   value = dot1dBasePort
    VLAN-aware switches (most Aruba CX / ProCurve). Gives us the VLAN too.
  * BRIDGE dot1dTpFdbPort (1.3.6.1.2.1.17.4.3.1.2)      [fallback]
        index = mac(6 octets)                value = dot1dBasePort
    Non-VLAN-aware / older gear.
  * dot1dBasePortIfIndex (1.3.6.1.2.1.17.1.4.1.2)
        index = dot1dBasePort                value = ifIndex
    Maps the bridge port number onto the ifIndex the interface poll uses. When
    a switch omits it we assume basePort == ifIndex (true on some platforms).
  * ifName (1.3.6.1.2.1.31.1.1.1.1) for a human port label.

Output: a list of records, one per learned MAC:
    {mac, mac_fmt, vlan, ifindex, ifname, port_mac_count}
``port_mac_count`` is how many MACs were learned on that same port — the edge-
port heuristic uses it (an access port learns 1-3 MACs; an uplink/trunk learns
everything downstream), so the smallest count is the device's real edge port.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

log = logging.getLogger(__name__)

OID_Q_FDB_PORT  = "1.3.6.1.2.1.17.7.1.2.2.1.2"   # dot1qTpFdbPort
OID_D_FDB_PORT  = "1.3.6.1.2.1.17.4.3.1.2"        # dot1dTpFdbPort (fallback)
OID_BASEPORT_IF = "1.3.6.1.2.1.17.1.4.1.2"        # dot1dBasePortIfIndex
OID_IF_NAME     = "1.3.6.1.2.1.31.1.1.1.1"        # ifName

WALK_BASES = [OID_Q_FDB_PORT, OID_D_FDB_PORT, OID_BASEPORT_IF, OID_IF_NAME]


def normalize_mac(s: str) -> Optional[str]:
    """Canonicalize any MAC spelling to 12 lowercase hex chars, or None.
    Accepts aa:bb:cc:dd:ee:ff, aa-bb-..., aabb.ccdd.eeff, AABBCCDDEEFF."""
    if not s:
        return None
    hexs = "".join(c for c in str(s).lower() if c in "0123456789abcdef")
    return hexs if len(hexs) == 12 else None


def format_mac(canon: str) -> str:
    """12-hex canonical -> aa:bb:cc:dd:ee:ff (best effort; returns input if odd)."""
    c = normalize_mac(canon)
    if not c:
        return str(canon)
    return ":".join(c[i:i + 2] for i in range(0, 12, 2))


def _mac_from_decimal_components(comps: List[str]) -> Optional[str]:
    """['0','17','34',...] (6 decimal octets) -> 'aabbcc...' canonical."""
    if len(comps) != 6:
        return None
    try:
        octets = [int(x) & 0xFF for x in comps]
    except (TypeError, ValueError):
        return None
    return "".join(f"{o:02x}" for o in octets)


def _parse_suffix_q(suffix: str):
    """dot1qTpFdbPort suffix 'fdbid.o1.o2.o3.o4.o5.o6' -> (vlan:int, mac:str)."""
    parts = suffix.split(".")
    if len(parts) != 7:
        return None
    mac = _mac_from_decimal_components(parts[1:7])
    if mac is None:
        return None
    try:
        vlan = int(parts[0])
    except ValueError:
        vlan = 0
    return vlan, mac


def _parse_suffix_d(suffix: str):
    """dot1dTpFdbPort suffix 'o1.o2.o3.o4.o5.o6' -> (0, mac)."""
    mac = _mac_from_decimal_components(suffix.split("."))
    return (0, mac) if mac else None


def assemble_fdb(columns: Dict[str, Dict[str, str]]) -> List[dict]:
    """Turn the walked columns (keyed OID base -> {suffix: value}) into MAC
    records. Prefers the Q-BRIDGE table; falls back to the plain bridge table
    only when Q-BRIDGE returned nothing."""
    q_fdb   = columns.get(OID_Q_FDB_PORT, {})
    d_fdb   = columns.get(OID_D_FDB_PORT, {})
    base_if = columns.get(OID_BASEPORT_IF, {})
    if_name = columns.get(OID_IF_NAME, {})

    # bridge port -> ifIndex (fall back to identity when the map is absent)
    port_to_if = {}
    for bp, ifidx in base_if.items():
        try:
            port_to_if[bp.strip()] = str(int(str(ifidx).strip()))
        except (TypeError, ValueError):
            continue

    def resolve_if(bridge_port: str) -> Optional[str]:
        bp = str(bridge_port).strip()
        if not bp or bp == "0":               # 0 = "not learned on a port"
            return None
        return port_to_if.get(bp, bp)         # identity fallback

    raw = []          # (vlan, mac, ifindex)
    if q_fdb:
        for suffix, port in q_fdb.items():
            parsed = _parse_suffix_q(suffix)
            if not parsed:
                continue
            vlan, mac = parsed
            ifidx = resolve_if(port)
            if ifidx:
                raw.append((vlan, mac, ifidx))
    else:
        for suffix, port in d_fdb.items():
            parsed = _parse_suffix_d(suffix)
            if not parsed:
                continue
            vlan, mac = parsed
            ifidx = resolve_if(port)
            if ifidx:
                raw.append((vlan, mac, ifidx))

    # de-dupe (same mac can appear per-VLAN); count distinct MACs per ifIndex.
    seen = set()
    per_if_macs: Dict[str, set] = {}
    deduped = []
    for vlan, mac, ifidx in raw:
        key = (mac, ifidx)
        per_if_macs.setdefault(ifidx, set()).add(mac)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((vlan, mac, ifidx))

    records = []
    for vlan, mac, ifidx in deduped:
        records.append({
            "mac":            mac,
            "mac_fmt":        format_mac(mac),
            "vlan":           vlan,
            "ifindex":        ifidx,
            "ifname":         if_name.get(ifidx, f"if{ifidx}"),
            "port_mac_count": len(per_if_macs.get(ifidx, ())),
        })
    return records


def collect(snmp, host: str, profile_name: Optional[str] = None) -> Optional[List[dict]]:
    """Walk the bridge MIBs for one host and assemble MAC records.
    Returns a list (possibly empty) or None on SNMP failure."""
    walked = snmp.bulk_walk(host, WALK_BASES, profile_name=profile_name)
    if walked is None:
        return None
    return assemble_fdb(walked)
