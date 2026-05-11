"""
SNMPv3 profile registry — multi-credential support.

Why this exists
---------------
Real fleets aren't single-credential. The agent's been operating one
switch fleet that mixes Aruba CX (which needs an SNMP context like
``network``) with Cisco IOS-XE and Arista EOS (which want the empty
default context). A single ``[snmp]`` block can't satisfy both: the
wrong context is rejected with ``authorizationError`` and the
agent's failure-retry path then amplifies the asyncio leak in
pysnmp's dispatcher.

The fix is profiles. Each ``[snmp.<name>]`` section defines a
self-contained set of credentials + context. The vendor detector
tries profiles until one succeeds against a host, then writes the
winning profile name to ``SwitchState.snmp_profile`` so subsequent
polls go straight to the right one — no retry storm, no compound
leak.

This module is C6.1: foundation only. We parse the config and
expose the registry. The SwitchMonitor + detector wiring lands
in C6.2.

Backward compatibility
----------------------
If the running config has the v3.0.0-style single ``[snmp]``
section with credentials inline (no ``[snmp.<name>]`` subsections),
the registry treats it as a single profile named ``default`` so
existing deployments keep working unchanged. Operators can split
into multiple profiles later via the Settings UI.
"""

from __future__ import annotations

import logging
from configparser import ConfigParser
from dataclasses  import dataclass
from typing       import Dict, List, Optional

from aruba_agent.secrets_store import decrypt as _decrypt
from aruba_agent.snmp           import SnmpV3Credentials


log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SnmpProfile:
    """
    A single named SNMPv3 profile. Holds everything needed to issue
    an authenticated GET against a host: credentials, transport
    parameters, and the SNMPv3 context this profile uses.

    Profiles are immutable; if the operator edits a profile in the
    Settings UI, the registry is rebuilt from the new config rather
    than mutated in place. That keeps the SwitchMonitor's read of
    "what profile am I using for host X" race-free.
    """
    name:    str                       # e.g. 'aruba', 'cisco', 'default'
    creds:   SnmpV3Credentials
    port:    int = 161
    timeout: int = 2
    retries: int = 1


class SnmpProfileRegistry:
    """
    Container for the set of profiles loaded from config, plus the
    name of the default profile. The default is what the detector
    tries first against a never-classified host, and what
    ``[snmp.<name>]``-less deployments use exclusively.
    """

    DEFAULT_PROFILE_NAME = "default"

    def __init__(
        self,
        profiles: Dict[str, SnmpProfile],
        default_name: str = DEFAULT_PROFILE_NAME,
    ) -> None:
        self._profiles = dict(profiles)
        self._default  = (
            default_name
            if default_name and default_name in self._profiles
            else (next(iter(self._profiles)) if self._profiles else "")
        )

    # ─── lookups ─────────────────────────────────────────────────────────────

    def get(self, name: str) -> Optional[SnmpProfile]:
        """Return the profile by name or None if not found."""
        return self._profiles.get(name)

    def default(self) -> Optional[SnmpProfile]:
        """Return the configured default profile."""
        return self._profiles.get(self._default)

    @property
    def default_name(self) -> str:
        return self._default

    def names(self) -> List[str]:
        """All profile names, default first then the rest in config order."""
        if not self._profiles:
            return []
        rest = [n for n in self._profiles.keys() if n != self._default]
        return [self._default] + rest if self._default else rest

    def __len__(self) -> int:
        return len(self._profiles)

    def __contains__(self, name: str) -> bool:
        return name in self._profiles

    def __iter__(self):
        for name in self.names():
            yield self._profiles[name]


# ─── config parsing ───────────────────────────────────────────────────────────

def _parse_one_profile(name: str, sec) -> Optional[SnmpProfile]:
    """
    Build one SnmpProfile from a config section. Returns None if the
    section is unusable (blank username, etc.) — callers can skip
    silently instead of crashing the agent.
    """
    username = (sec.get("username", "") or "").strip()
    if not username:
        log.warning("SNMP profile %r has no username — skipping", name)
        return None

    # auth_password / priv_password may be stored as enc:<token> on
    # disk (v3.0.1+). We decrypt at parse time so the rest of the
    # SNMP stack continues to see cleartext as it always has.
    creds = SnmpV3Credentials(
        username          = username,
        auth_protocol     = (sec.get("auth_protocol", "SHA") or "SHA").strip(),
        auth_password     = _decrypt(sec.get("auth_password", "") or ""),
        priv_protocol     = (sec.get("priv_protocol", "AES128") or "AES128").strip(),
        priv_password     = _decrypt(sec.get("priv_password", "") or ""),
        context_name      = (sec.get("context_name", "") or "").strip(),
        context_engine_id = (sec.get("context_engine_id", "") or "").strip(),
    )
    try:
        port    = int(sec.get("port",    "161") or "161")
        timeout = int(sec.get("timeout", "2")   or "2")
        retries = int(sec.get("retries", "1")   or "1")
    except (ValueError, TypeError):
        log.warning("SNMP profile %r has bad numeric fields — using defaults", name)
        port, timeout, retries = 161, 2, 1

    return SnmpProfile(
        name    = name,
        creds   = creds,
        port    = port,
        timeout = timeout,
        retries = retries,
    )


def from_config(cfg: ConfigParser) -> SnmpProfileRegistry:
    """
    Build a SnmpProfileRegistry from a parsed config.

    Two supported shapes:

    1. **New (multi-profile)** — ``[snmp.<name>]`` sections each
       carry their own credentials. ``[snmp] default_profile``
       names which one to try first.

           [snmp]
           enabled         = true
           default_profile = aruba

           [snmp.aruba]
           username = nets
           context_name = network
           ...

           [snmp.cisco]
           username = nets
           context_name =
           ...

    2. **Legacy (single profile)** — credentials live directly in
       ``[snmp]``. Treated as one profile called ``default``.

           [snmp]
           enabled = true
           username = nets
           context_name = network
           ...

    An empty registry is returned (zero profiles) if SNMP is
    disabled, or if no usable profile sections were found. Callers
    decide what to do — typically fall back to REST polling.
    """
    if not cfg.has_section("snmp"):
        return SnmpProfileRegistry({})

    main = cfg["snmp"]
    if (main.get("enabled", "false") or "false").strip().lower() not in (
        "true", "1", "yes", "on"
    ):
        return SnmpProfileRegistry({})

    profiles: Dict[str, SnmpProfile] = {}

    # New format: [snmp.<name>] sections.
    # Skip pseudo-sections like [snmp.context_name_aruba_cx] from C6's
    # earlier per-vendor-context experiment — those are legacy single-
    # profile artifacts and live inside [snmp] as keys, not subsections.
    for section in cfg.sections():
        if not section.startswith("snmp."):
            continue
        name = section[len("snmp."):]
        # Defensive: skip empty / whitespace names
        if not name.strip():
            continue
        profile = _parse_one_profile(name, cfg[section])
        if profile is not None:
            profiles[name] = profile

    # Legacy fallback: if no [snmp.<name>] sections were defined,
    # treat the contents of [snmp] itself as a single 'default' profile.
    if not profiles:
        legacy = _parse_one_profile(SnmpProfileRegistry.DEFAULT_PROFILE_NAME, main)
        if legacy is not None:
            profiles[SnmpProfileRegistry.DEFAULT_PROFILE_NAME] = legacy

    default_name = (main.get("default_profile", "") or "").strip()
    if not default_name:
        default_name = SnmpProfileRegistry.DEFAULT_PROFILE_NAME

    if profiles:
        log.info(
            "SNMP profile registry: %d profile(s) loaded (default=%s, others=%s)",
            len(profiles),
            default_name if default_name in profiles else next(iter(profiles)),
            ", ".join(n for n in profiles if n != default_name) or "(none)",
        )
    else:
        log.warning("SNMP enabled but no usable profiles found — agent will "
                    "fall back to REST polling")

    return SnmpProfileRegistry(profiles, default_name)
