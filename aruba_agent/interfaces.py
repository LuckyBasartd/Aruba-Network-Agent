"""
Interface statistics collector (SNMP ifTable / ifXTable).

Pure, testable core for interface-level monitoring: it turns SNMP column walks
into per-interface rows, filters to physical ports, and computes utilization
from 64-bit counter deltas. The actual SNMP I/O is a single GETBULK-based
`snmp.bulk_walk` call (see snmp.py); everything else here is pure Python.

See INTERFACE_MONITORING_SPEC.md for the design + anti-chatter controls.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

log = logging.getLogger(__name__)

# Column base OIDs. ifXTable (31.1.1.1.x) gives 64-bit counters + ifName/alias/
# highspeed; ifTable (2.2.1.x) gives status/errors/discards/type.
OIDS = {
    "if_name":     "1.3.6.1.2.1.31.1.1.1.1",
    "if_alias":    "1.3.6.1.2.1.31.1.1.1.18",
    "high_speed":  "1.3.6.1.2.1.31.1.1.1.15",   # Mbit/s
    "hc_in":       "1.3.6.1.2.1.31.1.1.1.6",     # ifHCInOctets
    "hc_out":      "1.3.6.1.2.1.31.1.1.1.10",    # ifHCOutOctets
    "oper":        "1.3.6.1.2.1.2.2.1.8",        # ifOperStatus (1=up)
    "admin":       "1.3.6.1.2.1.2.2.1.7",        # ifAdminStatus (1=up)
    "in_err":      "1.3.6.1.2.1.2.2.1.14",
    "out_err":     "1.3.6.1.2.1.2.2.1.20",
    "in_disc":     "1.3.6.1.2.1.2.2.1.13",
    "out_disc":    "1.3.6.1.2.1.2.2.1.19",
    "if_type":     "1.3.6.1.2.1.2.2.1.3",        # 6 = ethernetCsmacd
    "fcs_err":     "1.3.6.1.2.1.10.7.2.1.3",     # dot3StatsFCSErrors (real CRC)
}

# The columns we actually walk (skip alias if you want fewer varbinds).
WALK_KEYS = list(OIDS.keys())

_ETHERNET = 6           # ifType ethernetCsmacd
_OPER = {"1": "up", "2": "down", "3": "testing", "4": "unknown",
         "5": "dormant", "6": "notPresent", "7": "lowerLayerDown"}
_ADMIN = {"1": "up", "2": "down", "3": "testing"}


def _int(v, default=0):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def assemble_rows(columns: Dict[str, Dict[str, str]],
                  physical_only: bool = True) -> Dict[str, dict]:
    """Turn {oid_key: {ifIndex: value}} into {ifIndex: {fields}}.

    ``columns`` is keyed by the OIDS keys (if_name, hc_in, ...). Physical-only
    keeps ifType == ethernetCsmacd(6)."""
    # Union of all ifIndex suffixes seen across columns.
    indices = set()
    for col in columns.values():
        indices.update(col.keys())

    rows: Dict[str, dict] = {}
    for idx in indices:
        if physical_only:
            iftype = _int(columns.get("if_type", {}).get(idx), 0)
            if iftype != _ETHERNET:
                continue
        oper = columns.get("oper", {}).get(idx, "")
        admin = columns.get("admin", {}).get(idx, "")
        rows[idx] = {
            "ifIndex":    idx,
            "name":       columns.get("if_name", {}).get(idx, f"if{idx}"),
            "alias":      columns.get("if_alias", {}).get(idx, ""),
            "speed_mbps": _int(columns.get("high_speed", {}).get(idx), 0),
            "oper":       _OPER.get(str(oper).strip(), str(oper)),
            "admin":      _ADMIN.get(str(admin).strip(), str(admin)),
            "hc_in":      _int(columns.get("hc_in", {}).get(idx), 0),
            "hc_out":     _int(columns.get("hc_out", {}).get(idx), 0),
            "in_err":     _int(columns.get("in_err", {}).get(idx), 0),
            "crc_err":    _int(columns.get("fcs_err", {}).get(idx), 0),
            "out_err":    _int(columns.get("out_err", {}).get(idx), 0),
            "in_disc":    _int(columns.get("in_disc", {}).get(idx), 0),
            "out_disc":   _int(columns.get("out_disc", {}).get(idx), 0),
        }
    return rows


def compute_util(prev_octets: Optional[int], curr_octets: int,
                 elapsed_s: float, speed_mbps: int) -> Optional[float]:
    """Utilization % from a counter delta. None when it can't be computed:
    first sample (prev is None), no elapsed time, no speed, or a counter
    reset/wrap (delta < 0)."""
    if prev_octets is None or elapsed_s <= 0 or speed_mbps <= 0:
        return None
    delta = curr_octets - prev_octets
    if delta < 0:                       # counter wrap / device reboot
        return None
    bits = delta * 8
    capacity = speed_mbps * 1_000_000 * elapsed_s
    if capacity <= 0:
        return None
    return round(min(100.0, bits / capacity * 100.0), 2)


def collect(snmp, host: str, profile_name: Optional[str] = None,
            physical_only: bool = True) -> Optional[Dict[str, dict]]:
    """GETBULK-walk the interface columns for one host and assemble rows.
    Returns {ifIndex: row} or None on SNMP failure."""
    base_to_key = {OIDS[k]: k for k in WALK_KEYS}
    walked = snmp.bulk_walk(host, list(base_to_key.keys()),
                            profile_name=profile_name)
    if walked is None:
        return None
    # Re-key from base-oid -> our field key.
    columns = {base_to_key[b]: v for b, v in walked.items() if b in base_to_key}
    return assemble_rows(columns, physical_only=physical_only)
