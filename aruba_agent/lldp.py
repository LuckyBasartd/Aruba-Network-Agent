"""
LLDP / CDP neighbor collector — "what is attached to each port".

Pure, testable core (SNMP I/O is a single snmp.bulk_walk). Prefers LLDP
(vendor-neutral; Aruba CX / ProCurve / AOS all speak it) and falls back to
Cisco CDP where LLDP is absent. Each neighbor is classified into a device type
from the protocol's capability bits, so the UI can say switch / VoIP phone /
wireless AP / router / host per port.

LLDP-MIB (IEEE 802.1AB):
  lldpRemTable index = lldpRemTimeMark . lldpRemLocalPortNum . lldpRemIndex
    .7  lldpRemPortId          .8 lldpRemPortDesc   .9 lldpRemSysName
    .10 lldpRemSysDesc         .12 lldpRemSysCapEnabled (BITS)
  lldpLocPortTable index = lldpLocPortNum
    .2 lldpLocPortIdSubtype    .3 lldpLocPortId   (usually the ifName, e.g. 1/1/1)

  lldpRemSysCapEnabled BITS (bit 0 = MSB of first octet):
    0 other  1 repeater  2 bridge  3 wlanAccessPoint  4 router
    5 telephone  6 docsis  7 stationOnly

CISCO-CDP-MIB:
  cdpCacheTable index = cdpCacheIfIndex . cdpCacheDeviceIndex   (ifIndex direct!)
    .6 cdpCacheDeviceId  .7 cdpCacheDevicePort  .8 cdpCachePlatform
    .9 cdpCacheCapabilities (4-byte int bitmask)
      0x01 router  0x02 transparentBridge  0x04 sourceRouteBridge
      0x08 switch  0x10 host  0x40 repeater  0x80 phone
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

log = logging.getLogger(__name__)

# LLDP
OID_LLDP_REM_PORTID   = "1.0.8802.1.1.2.1.4.1.1.7"
OID_LLDP_REM_PORTDESC = "1.0.8802.1.1.2.1.4.1.1.8"
OID_LLDP_REM_SYSNAME  = "1.0.8802.1.1.2.1.4.1.1.9"
OID_LLDP_REM_SYSDESC  = "1.0.8802.1.1.2.1.4.1.1.10"
OID_LLDP_REM_CAP_ENA  = "1.0.8802.1.1.2.1.4.1.1.12"
OID_LLDP_LOC_PORTID   = "1.0.8802.1.1.2.1.3.7.1.3"
# CDP
OID_CDP_DEVICEID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
OID_CDP_DEVPORT  = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
OID_CDP_PLATFORM = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"
OID_CDP_CAPS     = "1.3.6.1.4.1.9.9.23.1.2.1.1.9"
# shared
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"

WALK_BASES = [
    OID_LLDP_REM_PORTID, OID_LLDP_REM_PORTDESC, OID_LLDP_REM_SYSNAME,
    OID_LLDP_REM_SYSDESC, OID_LLDP_REM_CAP_ENA, OID_LLDP_LOC_PORTID,
    OID_CDP_DEVICEID, OID_CDP_DEVPORT, OID_CDP_PLATFORM, OID_CDP_CAPS,
    OID_IF_NAME,
]


def _hex_bytes(pretty: str) -> List[int]:
    """Turn a pysnmp OctetString prettyPrint ('0x2800', '28 00', ...) into a
    list of byte ints. Non-hex input -> []."""
    if pretty is None:
        return []
    s = str(pretty).lower().replace("0x", "").replace(":", " ")
    hexs = "".join(c for c in s if c in "0123456789abcdef ")
    hexs = hexs.replace(" ", "")
    if len(hexs) % 2:
        hexs = "0" + hexs
    try:
        return [int(hexs[i:i + 2], 16) for i in range(0, len(hexs), 2)]
    except ValueError:
        return []


def _bit_set(bs: List[int], bit: int) -> bool:
    """LLDP BITS numbering: bit 0 is the MSB of the first octet."""
    octet = bit // 8
    if octet >= len(bs):
        return False
    return bool(bs[octet] & (0x80 >> (bit % 8)))


def classify_lldp(cap_pretty: str) -> str:
    bs = _hex_bytes(cap_pretty)
    if not bs:
        return "unknown"
    if _bit_set(bs, 3):
        return "wireless-ap"
    if _bit_set(bs, 5):
        return "voip-phone"
    if _bit_set(bs, 2):
        return "switch"
    if _bit_set(bs, 4):
        return "router"
    if _bit_set(bs, 7):
        return "host"
    return "other"


def classify_cdp(caps_pretty: str) -> str:
    """CDP capabilities are a 4-byte integer bitmask."""
    bs = _hex_bytes(caps_pretty)
    val = 0
    for b in bs:
        val = (val << 8) | b
    if not val:
        # some agents render it as a plain decimal string
        try:
            val = int(str(caps_pretty).strip())
        except (TypeError, ValueError):
            return "unknown"
    if val & 0x80:
        return "voip-phone"
    if val & 0x08 or val & 0x02:
        return "switch"
    if val & 0x01:
        return "router"
    if val & 0x10:
        return "host"
    return "other"


def _local_port_num(suffix: str) -> Optional[str]:
    """lldpRemTable suffix = timemark.localportnum.remindex -> localportnum."""
    parts = suffix.split(".")
    return parts[1] if len(parts) >= 3 else None


def assemble_lldp(columns: Dict[str, Dict[str, str]]) -> List[dict]:
    loc_portid = columns.get(OID_LLDP_LOC_PORTID, {})   # {portnum: "1/1/1"}
    sysname = columns.get(OID_LLDP_REM_SYSNAME, {})
    portid  = columns.get(OID_LLDP_REM_PORTID, {})
    portdsc = columns.get(OID_LLDP_REM_PORTDESC, {})
    sysdesc = columns.get(OID_LLDP_REM_SYSDESC, {})
    capena  = columns.get(OID_LLDP_REM_CAP_ENA, {})

    out = []
    for suffix, name in sysname.items():
        pnum = _local_port_num(suffix)
        if pnum is None:
            continue
        ifname = loc_portid.get(pnum) or f"port{pnum}"
        out.append({
            "ifname":      ifname,
            "protocol":    "lldp",
            "neighbor":    (name or "").strip(),
            "rem_port":    (portid.get(suffix) or portdsc.get(suffix) or "").strip(),
            "rem_desc":    (sysdesc.get(suffix) or "").strip(),
            "device_type": classify_lldp(capena.get(suffix, "")),
        })
    return out


def assemble_cdp(columns: Dict[str, Dict[str, str]]) -> List[dict]:
    if_name  = columns.get(OID_IF_NAME, {})
    devid    = columns.get(OID_CDP_DEVICEID, {})
    devport  = columns.get(OID_CDP_DEVPORT, {})
    platform = columns.get(OID_CDP_PLATFORM, {})
    caps     = columns.get(OID_CDP_CAPS, {})

    out = []
    for suffix, name in devid.items():
        ifidx = suffix.split(".")[0]      # cdpCacheIfIndex . deviceIndex
        ifname = if_name.get(ifidx, f"if{ifidx}")
        out.append({
            "ifname":      ifname,
            "protocol":    "cdp",
            "neighbor":    (name or "").strip(),
            "rem_port":    (devport.get(suffix) or "").strip(),
            "rem_desc":    (platform.get(suffix) or "").strip(),
            "device_type": classify_cdp(caps.get(suffix, "")),
        })
    return out


def assemble(columns: Dict[str, Dict[str, str]]) -> List[dict]:
    """LLDP first; add CDP entries for ports LLDP didn't already cover."""
    lldp = assemble_lldp(columns)
    seen = {r["ifname"] for r in lldp}
    cdp = [r for r in assemble_cdp(columns) if r["ifname"] not in seen]
    return lldp + cdp


def collect(snmp, host: str, profile_name: Optional[str] = None) -> Optional[List[dict]]:
    walked = snmp.bulk_walk(host, WALK_BASES, profile_name=profile_name)
    if walked is None:
        return None
    return assemble(walked)
