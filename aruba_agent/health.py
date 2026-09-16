"""
Device health collector — CPU %, memory used %, temperature (C).

Vendor SNMP MIBs for these are fragmented, so this keeps a per-vendor OID table
with standard-MIB fallbacks (HOST-RESOURCES for CPU, ENTITY-SENSOR for temp).
collect() is best-effort: it returns whatever it can read and None for the
rest, and never raises. The pure helpers (memory %, temp scaling, CPU average)
are unit-tested; the exact OIDs are easy to correct here after validating with
`main.py --health-once --host <ip>`.

Returned dict: {"cpu": float|None, "memory": float|None, "temperature": float|None}
  * cpu         — percent busy (0..100)
  * memory      — percent USED (0..100)
  * temperature — degrees Celsius (max sensor)
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

log = logging.getLogger(__name__)

# Standard MIBs (work on many platforms; used as fallback / for Aruba CX)
OID_HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"     # hrProcessorLoad (walk, %)
OID_ENTPHYSENSOR_VAL  = "1.3.6.1.2.1.99.1.1.1.4"     # entPhySensorValue (walk)
OID_ENTPHYSENSOR_TYPE = "1.3.6.1.2.1.99.1.1.1.1"     # entPhySensorType (8=celsius)
OID_ENTPHYSENSOR_SCALE= "1.3.6.1.2.1.99.1.1.1.2"     # entPhySensorScale
OID_ENTPHYSENSOR_PREC = "1.3.6.1.2.1.99.1.1.1.3"     # entPhySensorPrecision

# Per-vendor overrides. cpu/temp are lists of column OIDs to WALK; mem_* are
# scalar OIDs to GET. Values here are best-effort defaults — validate per model.
VENDOR_OIDS: Dict[str, dict] = {
    "aruba_cx": {
        "cpu_walk":  [OID_HR_PROCESSOR_LOAD],
        "temp_entity": True,
        # Aruba CX memory: prefer HOST-RESOURCES hrStorage (handled generically)
    },
    "aruba_os": {   # ProCurve / ArubaOS-Switch (HP enterprise 11)
        "cpu_get":   "1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0",              # hpSwitchCpuStat
        "mem_total": "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5.1",        # hpLocalMemTotalBytes
        "mem_alloc": "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7.1",        # hpLocalMemAllocatedBytes
        "temp_entity": True,
    },
    "cisco_ios": {
        "cpu_walk":  ["1.3.6.1.4.1.9.9.109.1.1.1.1.8"],                 # cpmCPUTotal5minRev
        "mem_used":  "1.3.6.1.4.1.9.9.48.1.1.1.5.1",                    # ciscoMemoryPoolUsed
        "mem_free":  "1.3.6.1.4.1.9.9.48.1.1.1.6.1",                    # ciscoMemoryPoolFree
        "temp_walk": ["1.3.6.1.4.1.9.9.13.1.3.1.3"],                    # ciscoEnvMonTemperatureValue
    },
}


def _num(v) -> Optional[float]:
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def compute_mem_pct(used, total) -> Optional[float]:
    u, t = _num(used), _num(total)
    if u is None or t is None or t <= 0:
        return None
    return round(min(100.0, max(0.0, u / t * 100.0)), 1)


def average(vals: List[float]) -> Optional[float]:
    nums = [n for n in (_num(v) for v in vals) if n is not None]
    return round(sum(nums) / len(nums), 1) if nums else None


def max_temp(vals: List, scale: float = 1.0) -> Optional[float]:
    nums = [n for n in (_num(v) for v in vals) if n is not None]
    if not nums:
        return None
    return round(max(nums) * scale, 1)


# EntitySensorDataScale (RFC 3433): exponent relative to units(9)=10^0.
_SCALE_EXP = {1:-24,2:-21,3:-18,4:-15,5:-12,6:-9,7:-6,8:-3,9:0,10:3,11:6,12:9,13:12,14:15}
_SENSOR_CELSIUS = "8"   # entPhySensorType celsius(8)


def decode_entity_temp(walked: Dict[str, Dict[str, str]]) -> Optional[float]:
    """Decode ENTITY-SENSOR-MIB into the max Celsius reading, applying each
    sensor's entPhySensorScale + entPhySensorPrecision, and filtering to
    temperature (celsius) sensors only (so we don't pick up fan RPM/voltage)."""
    types = walked.get(OID_ENTPHYSENSOR_TYPE, {}) or {}
    vals  = walked.get(OID_ENTPHYSENSOR_VAL, {}) or {}
    scales= walked.get(OID_ENTPHYSENSOR_SCALE, {}) or {}
    precs = walked.get(OID_ENTPHYSENSOR_PREC, {}) or {}
    temps = []
    for idx, t in types.items():
        if str(t).strip() != _SENSOR_CELSIUS:
            continue
        v = _num(vals.get(idx))
        if v is None:
            continue
        try:
            scale = int(str(scales.get(idx, 9)).strip() or 9)
        except ValueError:
            scale = 9
        try:
            prec = int(str(precs.get(idx, 0)).strip() or 0)
        except ValueError:
            prec = 0
        reading = v * (10 ** _SCALE_EXP.get(scale, 0))
        if prec > 0:
            reading = reading / (10 ** prec)
        temps.append(reading)
    return round(max(temps), 1) if temps else None


def collect(snmp, host: str, vendor: str = "",
            profile_name: Optional[str] = None) -> Dict[str, Optional[float]]:
    """Best-effort read of cpu/memory/temperature for one host."""
    result: Dict[str, Optional[float]] = {"cpu": None, "memory": None, "temperature": None}
    vmap = VENDOR_OIDS.get(vendor or "", {})

    def _walk(oids):
        try:
            w = snmp.bulk_walk(host, oids, profile_name=profile_name)
        except Exception:
            return {}
        return w or {}

    def _get(oid):
        try:
            return snmp.get(host, oid, profile_name=profile_name)
        except Exception:
            return None

    def _walk_avg(cols):
        if not cols:
            return None
        w = _walk(cols)
        return average([v for c in cols for v in (w.get(c, {}) or {}).values()])

    # ── CPU: vendor OID, then HOST-RESOURCES hrProcessorLoad ──
    try:
        cpu = None
        if vmap.get("cpu_get"):
            cpu = _num(_get(vmap["cpu_get"]))
        if cpu is None:
            cpu = _walk_avg(vmap.get("cpu_walk"))
        if cpu is None:
            cpu = _walk_avg([OID_HR_PROCESSOR_LOAD])
        result["cpu"] = cpu
    except Exception as exc:
        log.debug("health: cpu read failed on %s (%s)", host, exc)

    # ── Memory %used: vendor OIDs, then HOST-RESOURCES hrStorage ──
    try:
        mem = None
        if vmap.get("mem_total") and vmap.get("mem_alloc"):
            mem = compute_mem_pct(_get(vmap["mem_alloc"]), _get(vmap["mem_total"]))
        if mem is None and vmap.get("mem_used") and vmap.get("mem_free"):
            u, f = _num(_get(vmap["mem_used"])), _num(_get(vmap["mem_free"]))
            if u is not None and f is not None:
                mem = compute_mem_pct(u, u + f)
        if mem is None:
            mem = _hr_storage_mem_pct(_walk([
                "1.3.6.1.2.1.25.2.3.1.2", "1.3.6.1.2.1.25.2.3.1.5",
                "1.3.6.1.2.1.25.2.3.1.6"]))
        result["memory"] = mem
    except Exception as exc:
        log.debug("health: mem read failed on %s (%s)", host, exc)

    # ── Temperature: vendor direct OID (e.g. Cisco), then ENTITY-SENSOR ──
    try:
        temp = None
        if vmap.get("temp_walk"):
            w = _walk(vmap["temp_walk"])
            temp = max_temp([v for c in vmap["temp_walk"] for v in (w.get(c, {}) or {}).values()])
        if temp is None:
            temp = decode_entity_temp(_walk([
                OID_ENTPHYSENSOR_TYPE, OID_ENTPHYSENSOR_VAL,
                OID_ENTPHYSENSOR_SCALE, OID_ENTPHYSENSOR_PREC]))
        result["temperature"] = temp
    except Exception as exc:
        log.debug("health: temp read failed on %s (%s)", host, exc)

    return result


_HR_RAM_TYPE = "1.3.6.1.2.1.25.2.1.2"   # hrStorageRam


def _hr_storage_mem_pct(walked: dict) -> Optional[float]:
    """From HOST-RESOURCES hrStorageTable, find the RAM row and compute used %."""
    types = walked.get("1.3.6.1.2.1.25.2.3.1.2", {}) or {}
    sizes = walked.get("1.3.6.1.2.1.25.2.3.1.5", {}) or {}
    useds = walked.get("1.3.6.1.2.1.25.2.3.1.6", {}) or {}
    for idx, t in types.items():
        if str(t).strip().endswith(_HR_RAM_TYPE) or str(t).strip() == _HR_RAM_TYPE:
            return compute_mem_pct(useds.get(idx), sizes.get(idx))
    # fallback: first storage row
    for idx in sizes:
        pct = compute_mem_pct(useds.get(idx), sizes.get(idx))
        if pct is not None:
            return pct
    return None
