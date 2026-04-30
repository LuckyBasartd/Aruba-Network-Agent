"""
Cisco IOS / IOS-XE driver.

Built on top of NAPALM, which wraps netmiko (SSH) for IOS family
devices and exposes a vendor-neutral set of operations. We adapt
NAPALM's surface to our SwitchDriver protocol so the rest of the
agent — poller, backup, ARP, future tasks — can talk to a Cisco
switch with the same code that talks to an Aruba CX.

NAPALM driver options
---------------------
NAPALM ships several Cisco drivers:

    napalm.get_network_driver('ios')      # IOS / IOS-XE — Catalyst, ISR
    napalm.get_network_driver('iosxr')    # IOS-XR — carrier-grade
    napalm.get_network_driver('nxos_ssh') # NX-OS — Nexus via SSH

Default here is 'ios' since that covers the Catalyst / IOS-XE fleet
the campus team already has. Override per-deployment via
``[credentials.cisco] napalm_driver = ...``.

Lazy import
-----------
napalm pulls in netmiko + paramiko + ncclient + jinja2 (~30 MB on
disk). It's lazy-imported inside login() so a missing dep degrades
gracefully — the agent still loads, this driver just refuses to
connect with an actionable error message.

Limitations (intentional, for now)
----------------------------------
* No firmware update path. Cisco firmware is its own can of worms
  (rommon, partition layout, image verify) and out of scope for C4.
* save_running_to_startup is implemented as ``write memory`` via
  napalm.cli — the device must accept that command. Newer IOS-XE
  in transactional mode would need ``commit`` instead, which would
  go through napalm.commit_config() in candidate-config flows.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from aruba_agent.drivers.base import ArpEntry, Facts


log = logging.getLogger(__name__)


class CiscoIOSDriver:
    """SwitchDriver implementation for Cisco IOS / IOS-XE."""

    vendor = "cisco_ios"

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        enable_secret: str = "",
        napalm_driver: str = "ios",
        timeout: int = 30,
    ) -> None:
        self.host          = host
        self._username     = username
        self._password     = password
        self._enable       = enable_secret
        self._driver_name  = napalm_driver
        self._timeout      = timeout
        self._device       = None     # napalm device instance, set after login
        self.error: str    = ""

    # ─── attributes the SwitchDriver protocol promises ───────────────────────

    @property
    def logged_in(self) -> bool:
        return self._device is not None

    # ─── lifecycle ──────────────────────────────────────────────────────────

    def login(self) -> bool:
        try:
            from napalm import get_network_driver
        except ImportError as exc:
            self.error = (
                "napalm not installed — pip3 install -r "
                "/opt/aruba-agent/requirements.txt "
                f"({type(exc).__name__}: {exc})"
            )
            log.warning(self.error)
            return False

        try:
            DriverCls = get_network_driver(self._driver_name)
        except Exception as exc:
            self.error = f"unknown napalm driver {self._driver_name!r}: {exc}"
            log.warning(self.error)
            return False

        optional: dict = {}
        if self._enable:
            optional["secret"] = self._enable

        try:
            device = DriverCls(
                hostname      = self.host,
                username      = self._username,
                password      = self._password,
                timeout       = self._timeout,
                optional_args = optional,
            )
            device.open()
            self._device = device
            return True
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            log.debug("Cisco IOS login failed for %s: %s", self.host, self.error)
            self._device = None
            return False

    def logout(self) -> None:
        if self._device is None:
            return
        try:
            self._device.close()
        except Exception as exc:
            log.debug("Cisco IOS logout error on %s: %s", self.host, exc)
        finally:
            self._device = None

    def __enter__(self) -> "CiscoIOSDriver":
        self.login()
        return self

    def __exit__(self, *exc) -> None:
        self.logout()

    # ─── health ─────────────────────────────────────────────────────────────

    def is_reachable(self) -> bool:
        if self._device is None:
            return False
        try:
            status = self._device.is_alive()
        except Exception as exc:
            self.error = str(exc)
            return False
        # napalm returns {'is_alive': bool}
        return bool(status.get("is_alive", False)) if isinstance(status, dict) else False

    # ─── identity ───────────────────────────────────────────────────────────

    def get_hostname(self) -> Optional[str]:
        f = self.get_facts()
        return f.hostname if f else None

    def get_facts(self) -> Optional[Facts]:
        if self._device is None:
            return None
        try:
            data = self._device.get_facts()
        except Exception as exc:
            self.error = str(exc)
            return None
        return Facts(
            hostname   = data.get("hostname",     "") or "",
            vendor     = self.vendor,
            model      = data.get("model",        "") or "",
            os_version = data.get("os_version",   "") or "",
            serial     = data.get("serial_number","") or "",
        )

    # ─── configuration ──────────────────────────────────────────────────────

    def get_running_config(self) -> Optional[bytes]:
        """
        Pull the running-config text and return it as bytes (matching
        AOS-CX's get_running_config shape so backup.py doesn't have
        to branch).
        """
        if self._device is None:
            return None
        try:
            cfg = self._device.get_config(retrieve="running")
        except Exception as exc:
            self.error = str(exc)
            return None
        if isinstance(cfg, dict):
            text = cfg.get("running") or ""
        else:
            text = str(cfg or "")
        return text.encode("utf-8") if text else None

    def save_running_to_startup(self) -> bool:
        """``write memory`` via the CLI passthrough — copies running →
        startup on a traditional IOS image."""
        if self._device is None:
            return False
        try:
            # napalm.cli takes a list of commands and returns
            # {cmd: output}. Success is signaled by the absence of an
            # exception; output text varies ("[OK]", "Building config…",
            # or empty depending on platform).
            self._device.cli(["write memory"])
            return True
        except Exception as exc:
            self.error = str(exc)
            return False

    # ─── operational ────────────────────────────────────────────────────────

    def cli(self, cmd: str) -> Optional[str]:
        if self._device is None:
            return None
        try:
            output = self._device.cli([cmd])
        except Exception as exc:
            self.error = str(exc)
            return None
        if isinstance(output, dict):
            return output.get(cmd)
        return None

    def get_arp_table(self) -> List[ArpEntry]:
        """
        NAPALM returns a list of dicts with keys:
            interface, mac, ip, age (float seconds)

        We map onto the vendor-neutral ArpEntry shape. Cisco IOS doesn't
        surface a per-entry VLAN through this API — the interface name
        usually contains it already (Vlan100 / Vlan10) so we leave
        ArpEntry.vlan empty rather than re-parsing.
        """
        if self._device is None:
            return []
        try:
            entries = self._device.get_arp_table()
        except Exception as exc:
            self.error = str(exc)
            return []

        out: List[ArpEntry] = []
        for e in entries or []:
            try:
                age = e.get("age")
                age_str = "" if age is None else str(age)
                out.append(ArpEntry(
                    ip        = e.get("ip", "")        or "",
                    mac       = e.get("mac", "")       or "",
                    interface = e.get("interface", "") or "",
                    age       = age_str,
                ))
            except (TypeError, AttributeError):
                continue
        return out
