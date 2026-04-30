"""
Arista EOS driver.

Built on NAPALM's ``eos`` driver, which talks to the switch via
Arista's eAPI (JSON-RPC over HTTP/HTTPS) — much faster than SSH and
the canonical way Arista intends programmatic access. eAPI must be
enabled on the switch:

    management api http-commands
       no shutdown
       protocol https
       !

Differences from the Cisco driver
---------------------------------
* Transport is HTTPS by default (eAPI), not SSH. Settable via the
  ``transport`` arg if a fleet uses HTTP-only management.
* The privileged-mode token is called ``enable_password`` (not
  ``enable_secret``) — just naming, same idea.
* save_running_to_startup runs ``copy running-config startup-config``
  via napalm.cli — Arista's equivalent of Cisco's ``write memory``.

Lazy import
-----------
napalm + pyeapi are imported inside login() so a missing dep
degrades gracefully — the rest of the agent stays loadable, this
driver just refuses to connect with an actionable error message.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from aruba_agent.drivers.base import ArpEntry, Facts


log = logging.getLogger(__name__)


class AristaEOSDriver:
    """SwitchDriver implementation for Arista EOS."""

    vendor = "arista_eos"

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        enable_password: str = "",
        transport: str = "https",
        port: Optional[int] = None,
        timeout: int = 30,
    ) -> None:
        self.host         = host
        self._username    = username
        self._password    = password
        self._enable      = enable_password
        self._transport   = transport
        self._port        = port
        self._timeout     = timeout
        self._device      = None
        self.error: str   = ""

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
            DriverCls = get_network_driver("eos")
        except Exception as exc:
            self.error = f"napalm 'eos' driver unavailable: {exc}"
            log.warning(self.error)
            return False

        optional: dict = {"transport": self._transport}
        if self._port is not None:
            optional["port"] = self._port
        if self._enable:
            optional["enable_password"] = self._enable

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
            log.debug("Arista EOS login failed for %s: %s", self.host, self.error)
            self._device = None
            return False

    def logout(self) -> None:
        if self._device is None:
            return
        try:
            self._device.close()
        except Exception as exc:
            log.debug("Arista EOS logout error on %s: %s", self.host, exc)
        finally:
            self._device = None

    def __enter__(self) -> "AristaEOSDriver":
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
        if self._device is None:
            return None
        try:
            cfg = self._device.get_config(retrieve="running")
        except Exception as exc:
            self.error = str(exc)
            return None
        text = cfg.get("running") if isinstance(cfg, dict) else str(cfg or "")
        return text.encode("utf-8") if text else None

    def save_running_to_startup(self) -> bool:
        """Arista's equivalent of Cisco's ``write memory``."""
        if self._device is None:
            return False
        try:
            self._device.cli(["copy running-config startup-config"])
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
