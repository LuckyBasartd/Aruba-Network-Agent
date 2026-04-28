"""
driver_for(host, ...) — pick a SwitchDriver implementation for a host.

Phase C1: always returns ArubaCXDriver. The factory exists today so
every consumer (poller, backup, ARP, firmware, scanner) can be
refactored to call `driver_for(...)` instead of `ArubaCXSession(...)`.
That refactor is mechanical; once it's in place, C3 will replace the
body of this function with real SNMPv3 sysObjectID detection plus
fallback REST/SSH probes — and no other code has to change.

Caching: not yet. C3 introduces a per-host detection cache so we
don't re-detect every poll. For now each call is independent.
"""

from __future__ import annotations

from typing import Optional

from aruba_agent.drivers.aruba_cx import ArubaCXDriver
from aruba_agent.drivers.base     import SwitchDriver


def driver_for(
    host: str,
    username: str,
    password: str,
    *,
    verify_ssl: bool = False,
    preferred_version: Optional[str] = None,
    vendor_hint: Optional[str] = None,
) -> SwitchDriver:
    """
    Return a SwitchDriver instance ready for `with driver_for(...) as drv`.

    Parameters
    ----------
    host : str
        IP or hostname of the switch.
    username, password : str
        Vendor-agnostic admin credentials. C4/C5 will accept per-vendor
        credential bundles; for now this matches ArubaCXSession's API.
    verify_ssl : bool
        TLS verification toggle. False on self-signed lab gear.
    preferred_version : str | None
        AOS-CX-specific API version pin (e.g. "v10.13"). Ignored by
        non-Aruba drivers.
    vendor_hint : str | None
        Reserved for C3. When the detector has already classified
        this host, the hint short-circuits re-detection. Currently
        unused — every host gets ArubaCXDriver.
    """
    # C3 will replace this body with vendor detection. The signature
    # stays stable so callers don't need to change again.
    _ = vendor_hint  # silences unused-arg in C1; C3 wires it up
    return ArubaCXDriver(
        host              = host,
        username          = username,
        password          = password,
        verify_ssl        = verify_ssl,
        preferred_version = preferred_version,
    )
