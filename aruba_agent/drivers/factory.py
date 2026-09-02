"""
driver_for(host, ...) — pick a SwitchDriver implementation for a host.

Routing
-------
Each call needs a way to know which vendor's driver to construct.
Order of preference:

    1. Explicit `vendor_hint=` from the caller — used when the
       caller already classified the host (e.g. switch_poller has
       SwitchState.vendor populated by the C3 detector).
    2. Default: AOS-CX. This keeps the v2.x behavior intact for
       installs that haven't yet enabled SNMPv3 + vendor detection.

Cisco-specific arguments
------------------------
NAPALM's IOS driver wants different things than AOS-CX REST: an
SSH username/password and an optional enable secret. We accept
those as separate parameters rather than overloading the generic
``username`` / ``password`` fields.

The factory does NOT consult [credentials.cisco] from disk itself —
the caller is expected to read config and pass the right values in.
That keeps factory pure (no I/O) and makes per-call overrides easy.
"""

from __future__ import annotations

import logging
from typing import Optional

from aruba_agent.drivers.aruba_cx import ArubaCXDriver
from aruba_agent.drivers.base     import SwitchDriver
from aruba_agent.drivers.detector import (
    VENDOR_ARUBA_CX, VENDOR_ARUBA_OS,
    VENDOR_CISCO_IOS, VENDOR_ARISTA,
)


log = logging.getLogger(__name__)


def driver_for(
    host: str,
    username: str,
    password: str,
    *,
    verify_ssl: bool = False,
    preferred_version: Optional[str] = None,
    vendor_hint: Optional[str] = None,
    # Cisco-specific overrides; ignored when the resolved vendor
    # isn't cisco_ios. If empty, fall back to username / password.
    cisco_username: str = "",
    cisco_password: str = "",
    cisco_enable:   str = "",
    cisco_napalm_driver: str = "ios",
    # v3.0.3: SSH public-key auth for Cisco (NAPALM via netmiko). When
    # set, NAPALM uses the key instead of cisco_password — leave
    # cisco_password empty for unencrypted keys, or set it to the
    # key's passphrase. Falls back to password auth when blank.
    cisco_key_file: str = "",
    # Arista-specific overrides; ignored when the resolved vendor
    # isn't arista_eos. If empty, fall back to username / password.
    arista_username:        str = "",
    arista_password:        str = "",
    arista_enable_password: str = "",
    arista_transport:       str = "https",
    arista_port:            Optional[int] = None,
    # Aruba OS-S (ProCurve) SSH overrides; ignored unless the resolved
    # vendor is aruba_os. If empty, fall back to username / password.
    arubaos_username:       str = "",
    arubaos_password:       str = "",
    arubaos_enable:         str = "",
) -> SwitchDriver:
    """
    Return a SwitchDriver instance ready for `with driver_for(...) as drv`.

    Parameters
    ----------
    host : str
        IP or hostname of the switch.
    username, password : str
        Default credentials. Used by AOS-CX. Used by Cisco only when
        cisco_username / cisco_password are blank.
    verify_ssl : bool
        TLS verification toggle (AOS-CX only). False on self-signed
        lab gear.
    preferred_version : str | None
        AOS-CX-specific API version pin (e.g. "v10.13"). Ignored by
        non-Aruba drivers.
    vendor_hint : str | None
        Vendor key from the C3 detector. When set to ``cisco_ios``
        we route to the NAPALM-backed CiscoIOSDriver; otherwise
        we fall through to ArubaCXDriver.
    cisco_username, cisco_password, cisco_enable, cisco_napalm_driver
        Cisco-specific credentials and NAPALM driver name. Ignored
        unless vendor_hint resolves to cisco_ios.
    """
    if vendor_hint == VENDOR_CISCO_IOS:
        from aruba_agent.drivers.cisco_ios import CiscoIOSDriver
        return CiscoIOSDriver(
            host          = host,
            username      = cisco_username or username,
            password      = cisco_password or password,
            enable_secret = cisco_enable,
            napalm_driver = cisco_napalm_driver,
            key_file      = cisco_key_file,
        )

    if vendor_hint == VENDOR_ARISTA:
        from aruba_agent.drivers.arista_eos import AristaEOSDriver
        return AristaEOSDriver(
            host            = host,
            username        = arista_username or username,
            password        = arista_password or password,
            enable_password = arista_enable_password,
            transport       = arista_transport,
            port            = arista_port,
        )

    if vendor_hint == VENDOR_ARUBA_OS:
        # ProCurve / ArubaOS-Switch: no REST API — drive over SSH CLI.
        from aruba_agent.drivers.aruba_os import ArubaOSDriver
        return ArubaOSDriver(
            host          = host,
            username      = arubaos_username or username,
            password      = arubaos_password or password,
            enable_secret = arubaos_enable,
        )

    # Default / AOS-CX path
    _ = vendor_hint  # accepted but unused beyond the routing above
    if vendor_hint not in (None, VENDOR_ARUBA_CX, VENDOR_ARISTA):
        log.warning("driver_for: unrecognized vendor_hint=%r for %s — "
                    "defaulting to AOS-CX", vendor_hint, host)
    return ArubaCXDriver(
        host              = host,
        username          = username,
        password          = password,
        verify_ssl        = verify_ssl,
        preferred_version = preferred_version,
    )
