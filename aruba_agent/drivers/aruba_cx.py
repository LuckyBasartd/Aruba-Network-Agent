"""
Aruba AOS-CX driver.

Thin adapter on top of the existing ArubaCXSession — keeps the proven
REST + CSRF + version-fallback + reliable-logout code from cx_session
and exposes it under the SwitchDriver protocol so the poller / backup
/ ARP / firmware tasks stop talking to ArubaCXSession directly.

For vendor-specific features that don't have a uniform shape across
vendors (firmware upload, raw CLI), callers can reach the underlying
ArubaCXSession via .session — the firmware updater uses this for
streamed image uploads. Cisco / Arista drivers will expose their own
escape hatches.
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional

from aruba_agent.cx_session     import ArubaCXSession
from aruba_agent.drivers.base   import ArpEntry, Facts


log = logging.getLogger(__name__)


class ArubaCXDriver:
    """SwitchDriver implementation for Aruba AOS-CX."""

    vendor = "aruba_cx"

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        verify_ssl: bool       = False,
        preferred_version: Optional[str] = None,
    ) -> None:
        self.host    = host
        self.session = ArubaCXSession(
            host              = host,
            username          = username,
            password          = password,
            verify_ssl        = verify_ssl,
            preferred_version = preferred_version,
        )

    # ─── attributes proxied to the underlying session ─────────────────────

    @property
    def logged_in(self) -> bool:
        return self.session.logged_in

    @property
    def error(self) -> str:
        return self.session.error

    # ─── lifecycle ────────────────────────────────────────────────────────

    def login(self) -> bool:
        return self.session.login()

    def logout(self) -> None:
        self.session.logout()

    def __enter__(self) -> "ArubaCXDriver":
        self.login()
        return self

    def __exit__(self, *exc) -> None:
        self.logout()

    # ─── health ───────────────────────────────────────────────────────────

    def is_reachable(self) -> bool:
        return self.session.is_reachable()

    # ─── identity ─────────────────────────────────────────────────────────

    def get_hostname(self) -> Optional[str]:
        return self.session.get_hostname()

    def get_facts(self) -> Optional[Facts]:
        """
        Pull /system once and unpack hostname / model / version. Other
        vendors will populate the same Facts shape from their own
        identification APIs.
        """
        resp = self.session._get("system")   # noqa: SLF001 — controlled access
        if resp is None or resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None

        # AOS-CX 10.x exposes platform_name / software_version directly on
        # /system. Older versions sometimes use different keys; we fall
        # back to empty strings rather than crashing the poller.
        return Facts(
            hostname   = data.get("hostname",          "") or "",
            vendor     = self.vendor,
            model      = data.get("platform_name",     "") or "",
            os_version = data.get("software_version",  "") or "",
            serial     = data.get("base_mac_address",  "") or "",
        )

    # ─── configuration ────────────────────────────────────────────────────

    def get_running_config(self) -> Optional[bytes]:
        """
        AOS-CX serves config best from /fullconfigs/startup-config after
        a write-mem. The backup task already does that
        (save_running_to_startup -> get_startup_config), so this
        method matches that flow.
        """
        return self.session.get_startup_config()

    def save_running_to_startup(self) -> bool:
        return self.session.save_running_to_startup()

    # ─── operational ──────────────────────────────────────────────────────

    def cli(self, cmd: str) -> Optional[str]:
        return self.session.cli(cmd)

    # ─── ARP table ────────────────────────────────────────────────────────

    # Matches "1.2.3.4   00:11:22:33:44:55  vlan123  1/1/24" type rows.
    # Tolerant of extra whitespace and a leading IPv6/IPv4 indicator column.
    _ARP_ROW = re.compile(
        r"^\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<mac>[0-9a-fA-F]{2}([:.\-][0-9a-fA-F]{2}){5})\s+"
        r"(?P<vlan>\S+)?\s*"
        r"(?P<intf>\S+)?\s*$"
    )

    def get_arp_table(self) -> List[ArpEntry]:
        """
        Return ARP entries scraped from `show arp` via the CLI API.
        Empty list on transport failure or parse miss.
        """
        text = self.cli("show arp")
        if not text:
            return []
        out: List[ArpEntry] = []
        for line in text.splitlines():
            m = self._ARP_ROW.match(line)
            if not m:
                continue
            out.append(ArpEntry(
                ip        = m.group("ip"),
                mac       = m.group("mac"),
                vlan      = m.group("vlan") or "",
                interface = m.group("intf") or "",
            ))
        return out
