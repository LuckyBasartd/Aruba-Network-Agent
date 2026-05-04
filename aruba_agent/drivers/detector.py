"""
Vendor detection via SNMPv3 sysObjectID.

Every SNMP-speaking device exposes ``sysObjectID.0`` (1.3.6.1.2.1.1.2.0)
which resolves to a vendor-assigned OID under the IANA enterprise tree
1.3.6.1.4.1.<n>. The first few sub-OIDs identify the vendor; the rest
identify the model. We don't need exact model identification here —
just "which driver class should handle this host?"

Supported prefixes (broadest match wins):

    1.3.6.1.4.1.47196      Aruba Networks (HPE) — AOS-CX 6300/6400/8xxx
    1.3.6.1.4.1.14823      Aruba Networks (legacy) — AOS-S / older
    1.3.6.1.4.1.11         HP/HPE Enterprise — some Aruba-branded gear
    1.3.6.1.4.1.9          Cisco Systems — IOS / IOS-XE / NX-OS / IOS-XR
    1.3.6.1.4.1.30065      Arista Networks — EOS

Anything else returns ``None``. Callers fall back to vendor-agnostic
behavior (e.g. SNMP-only reachability, no per-vendor backups).

Falls back to ``sysDescr.0`` keyword sniffing only if sysObjectID didn't
resolve to a known prefix — useful for occasional re-branded gear that
exposes a different enterprise OID but a clearly tagged vendor string.

Caching
-------
Detection is one round-trip per host the first time it's seen. Results
go into an in-process dict keyed by IP, protected by a lock for the
multi-thread SwitchMonitor pool. ``invalidate()`` is exposed for the
scanner to clear an entry when an IP was reassigned.

Threading
---------
Concurrent ``detect()`` calls on the same agent + different hosts are
safe — the underlying SnmpAgent is already thread-safe (per-thread
event loop and SnmpEngine cache from C2). The cache dict has its own
lock for read/write fences.
"""

from __future__ import annotations

import logging
import threading
from typing import Dict, Optional, Tuple

from aruba_agent.snmp import SnmpAgent


log = logging.getLogger(__name__)


# Vendor key strings — these match the `vendor` attribute on each
# concrete driver (ArubaCXDriver.vendor == "aruba_cx", etc.) so the
# factory can pass the result straight through.
VENDOR_ARUBA_CX  = "aruba_cx"
VENDOR_ARUBA_OS  = "aruba_os"     # legacy AOS-S / Switch — driver TBD
VENDOR_CISCO_IOS = "cisco_ios"
VENDOR_ARISTA    = "arista_eos"

# Enterprise-OID prefix → vendor key. Order matters only for prefixes
# that share a parent — longest match wins thanks to the sort below.
_PREFIX_TO_VENDOR: Tuple[Tuple[str, str], ...] = tuple(sorted(
    (
        ("1.3.6.1.4.1.47196",  VENDOR_ARUBA_CX),
        ("1.3.6.1.4.1.14823",  VENDOR_ARUBA_OS),
        ("1.3.6.1.4.1.11",     VENDOR_ARUBA_OS),     # HP/HPE — old Aruba kit
        ("1.3.6.1.4.1.9",      VENDOR_CISCO_IOS),
        ("1.3.6.1.4.1.30065",  VENDOR_ARISTA),
    ),
    key=lambda kv: -len(kv[0]),     # longest first → most specific match wins
))


# sysDescr keyword fallbacks — used when the OID didn't match anything we
# know but the descr string is unambiguous. Not authoritative; intended
# as a "we got something useful, route it" hint.
_DESCR_KEYWORDS: Tuple[Tuple[str, str], ...] = (
    ("ArubaOS-CX",        VENDOR_ARUBA_CX),
    ("Aruba JL",          VENDOR_ARUBA_CX),    # 6300/6400 hostname patterns
    ("Aruba",             VENDOR_ARUBA_OS),    # generic — last resort
    ("Cisco IOS",         VENDOR_CISCO_IOS),
    ("Cisco Internetwork",VENDOR_CISCO_IOS),
    ("Cisco Nexus",       VENDOR_CISCO_IOS),   # NX-OS — close enough for now
    ("Arista Networks",   VENDOR_ARISTA),
    ("EOS-",              VENDOR_ARISTA),
)


class VendorDetector:
    """
    Identifies the vendor of an SNMP-speaking host. Wraps an SnmpAgent
    and caches per-IP results.
    """

    def __init__(self, snmp_agent: SnmpAgent) -> None:
        self._snmp = snmp_agent
        # Cache: host -> (vendor, profile_name). The profile_name records
        # which SNMPv3 profile authenticated successfully for the host
        # so subsequent polls don't have to re-discover.
        self._cache: Dict[str, Tuple[str, str]] = {}
        self._lock  = threading.Lock()

    # ─── public API ──────────────────────────────────────────────────────────

    def detect(self, host: str) -> Optional[str]:
        """
        Return the vendor key for *host* (e.g. ``aruba_cx``) or None
        if the device didn't answer SNMP or sits outside the known
        prefix table.

        Backwards-compatible single-return form. Use
        ``detect_with_profile`` to get the SNMP profile name as well.
        """
        result = self.detect_with_profile(host)
        return result[0] if result else None

    def detect_with_profile(self, host: str) -> Optional[Tuple[str, str]]:
        """
        Try each SNMP profile in registry order until one returns a
        sysObjectID we can classify (or a sysDescr we recognize).
        Returns ``(vendor, profile_name)`` for the winning profile,
        or None if no profile authenticated + classified.

        Cached on first success per host. The caller (SwitchMonitor)
        also persists the winner on SwitchState so this lookup
        doesn't run on every poll.
        """
        with self._lock:
            cached = self._cache.get(host)
        if cached is not None:
            return cached

        # Iterate the registry's profiles. SnmpProfileRegistry yields
        # the default profile first then the rest in config order.
        for profile in self._snmp.registry:
            sys_obj = self._snmp.get_sys_object_id(
                host, profile_name=profile.name,
            )
            if sys_obj:
                normalized = sys_obj.strip().lstrip(".")
                for prefix, vendor in _PREFIX_TO_VENDOR:
                    if normalized == prefix or normalized.startswith(prefix + "."):
                        result = (vendor, profile.name)
                        with self._lock:
                            self._cache[host] = result
                        log.info("Vendor detected: %s → %s (profile=%s)",
                                 host, vendor, profile.name)
                        return result
                log.debug("sysObjectID %s on %s via profile %s did not match "
                          "any known prefix", normalized, host, profile.name)

            # sysDescr fallback — also scoped to this profile
            sys_descr = self._snmp.get_sys_descr(
                host, profile_name=profile.name,
            )
            if sys_descr:
                for kw, vendor in _DESCR_KEYWORDS:
                    if kw.lower() in sys_descr.lower():
                        result = (vendor, profile.name)
                        with self._lock:
                            self._cache[host] = result
                        log.info("Vendor detected: %s → %s (profile=%s, "
                                 "via sysDescr)", host, vendor, profile.name)
                        return result
                log.debug("sysDescr on %s via profile %s had no recognized "
                          "vendor keyword: %s", host, profile.name,
                          sys_descr[:120])

        return None

    def invalidate(self, host: str) -> None:
        """Drop the cached classification for *host*. Next call re-probes."""
        with self._lock:
            self._cache.pop(host, None)

    def known(self) -> Dict[str, Tuple[str, str]]:
        """Snapshot of all currently-cached (vendor, profile) classifications."""
        with self._lock:
            return dict(self._cache)

    # The C3 _classify() helper that iterated context overrides on a
    # single credential set has been removed. detect_with_profile()
    # iterates entire profiles instead — each profile carries its own
    # credentials AND context.


# ─── module-level helper for tests / quick scripts ───────────────────────────

def vendor_for_oid(sys_object_id: str) -> Optional[str]:
    """
    Pure-function classification — handy for unit tests and the
    `--detect` CLI dance. Returns None for unknowns.
    """
    if not sys_object_id:
        return None
    normalized = sys_object_id.strip().lstrip(".")
    for prefix, vendor in _PREFIX_TO_VENDOR:
        if normalized == prefix or normalized.startswith(prefix + "."):
            return vendor
    return None
