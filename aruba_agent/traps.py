"""
SNMP trap classification — pure, testable core for the trap receiver.

Turns a received trap (its snmpTrapOID + varbinds) into a normalized record
(name, category, severity) and decides whether it warrants an email under the
operator's alert policy. The pysnmp transport lives in trap_receiver.py; this
module has no I/O so it can be unit-tested exhaustively.

Categories:  system | link | auth | hardware | other
Severities:  critical | warning | info

Alert policy (config [traps] alert_policy):
  * "critical"        — system/auth/hardware warnings+ (NOT link changes)
  * "critical+linkdown" — the above, plus linkDown (linkUp still store-only)
  * "none"            — store everything, email nothing
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

# Standard SNMPv2-MIB / IF-MIB notification OIDs (snmpTrapOID.0 values)
GENERIC = {
    "1.3.6.1.6.3.1.1.5.1": ("coldStart",             "system", "warning"),
    "1.3.6.1.6.3.1.1.5.2": ("warmStart",             "system", "info"),
    "1.3.6.1.6.3.1.1.5.3": ("linkDown",              "link",   "warning"),
    "1.3.6.1.6.3.1.1.5.4": ("linkUp",                "link",   "info"),
    "1.3.6.1.6.3.1.1.5.5": ("authenticationFailure", "auth",   "warning"),
}

OID_IF_INDEX  = "1.3.6.1.2.1.2.2.1.1"
OID_IF_DESCR  = "1.3.6.1.2.1.2.2.1.2"
OID_IF_NAME   = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_OPER   = "1.3.6.1.2.1.2.2.1.8"

# Substrings (in the trap OID's resolved name or any varbind value) that mark a
# vendor/enterprise trap as a hardware/system fault worth alerting on.
_HARDWARE_HINTS = (
    "powersupply", "power supply", "psu", "power-supply",
    "fan", "temperature", "thermal", "overheat", "over-temp",
    "vsf", "stack", "member", "fabric", "fault", "failed", "failure",
    "redundan", "module down", "poweroff", "hotswap",
)
_DOWN_HINTS = ("down", "fail", "fault", "off", "removed", "critical", "major")


def _text_of(varbinds: List[Tuple[str, str]]) -> str:
    return " ".join(str(v) for _, v in (varbinds or [])).lower()


def extract_ifindex(varbinds: List[Tuple[str, str]]) -> Optional[str]:
    """Return the ifIndex from a link trap's varbinds, if present."""
    for oid, val in (varbinds or []):
        o = str(oid)
        if o == OID_IF_INDEX or o.startswith(OID_IF_INDEX + "."):
            s = str(val).strip()
            # value may be the index itself, or the OID tail carries it
            if s.isdigit():
                return s
            tail = o[len(OID_IF_INDEX) + 1:]
            if tail.isdigit():
                return tail
    return None


def classify_trap(trap_oid: str,
                  varbinds: Optional[List[Tuple[str, str]]] = None,
                  name_hint: str = "") -> Dict:
    """Classify a trap into {name, category, severity, oid, ifindex}.

    ``trap_oid`` is the numeric snmpTrapOID.0 value. ``name_hint`` is an
    optional human name the receiver already resolved (e.g. via a MIB); it and
    the varbind values feed the hardware-keyword heuristic for enterprise
    traps not in the generic table."""
    trap_oid = (trap_oid or "").strip()
    varbinds = varbinds or []
    if trap_oid in GENERIC:
        name, category, severity = GENERIC[trap_oid]
        rec = {"name": name, "category": category, "severity": severity,
               "oid": trap_oid, "ifindex": None}
        if category == "link":
            rec["ifindex"] = extract_ifindex(varbinds)
        return rec

    # Enterprise / unknown: sniff the name hint + varbind text for hardware.
    blob = (name_hint + " " + _text_of(varbinds)).lower()
    if any(h in blob for h in _HARDWARE_HINTS):
        severity = "critical" if any(d in blob for d in _DOWN_HINTS) else "warning"
        return {"name": name_hint or "enterprise-hardware",
                "category": "hardware", "severity": severity,
                "oid": trap_oid, "ifindex": None}
    return {"name": name_hint or "enterprise", "category": "other",
            "severity": "info", "oid": trap_oid, "ifindex": None}


_SEV_RANK = {"info": 0, "warning": 1, "critical": 2}


def should_alert(rec: Dict, policy: str = "critical") -> bool:
    """Decide whether a classified trap should email, per the alert policy."""
    policy = (policy or "critical").strip().lower()
    if policy == "none":
        return False
    category = rec.get("category")
    severity = rec.get("severity", "info")
    name = rec.get("name", "")
    sev_ok = _SEV_RANK.get(severity, 0) >= _SEV_RANK["warning"]

    # link traps are store-only under "critical"; linkDown emails under
    # "critical+linkdown"; linkUp never emails.
    if category == "link":
        return policy == "critical+linkdown" and name == "linkDown"

    # system: coldStart is worth an alert (unexpected reboot); warmStart isn't.
    if category == "system":
        return name == "coldStart"

    # auth + hardware: alert on warning or higher.
    if category in ("auth", "hardware"):
        return sev_ok
    return False
