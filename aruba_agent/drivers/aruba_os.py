"""
Aruba OS-S (formerly HP/HPE ProCurve, "ArubaOS-Switch") driver.

These are the 2530 / 2930F / 3810 class switches. Unlike AOS-CX
(6300/6400) they have *no* REST API — the AOS-CX driver's HTTPS
``/rest/v10.x`` login just times out against them. They are managed
over SSH CLI, so this driver drives them with netmiko's
``hp_procurve`` device type.

Why netmiko directly (not NAPALM): NAPALM has no core ProCurve
driver. netmiko does, and it already ships transitively with napalm
(used by the Cisco / Arista drivers), so there's no new dependency.
netmiko is imported lazily inside ``login()`` so a missing dep
degrades to a clear error rather than breaking agent startup.

Contract: this matches the SwitchDriver protocol in base.py. Like
the other drivers it never raises on transport errors — it returns
None / [] / False and records the reason in ``self.error``.

Manager mode
------------
``show running-config`` requires manager (enable) privilege on
ProCurve. If the login account is only operator level, pass an
enable secret via ``[credentials.aruba_os] enable_secret`` and this
driver will ``enable()`` after login. Many campus deployments log
the monitoring account straight into manager mode, in which case no
secret is needed.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from aruba_agent.drivers.base import ArpEntry, Facts
from aruba_agent.secrets_store import redact as _redact


log = logging.getLogger(__name__)


class ArubaOSDriver:
    """SwitchDriver implementation for Aruba OS-S / ProCurve over SSH."""

    vendor = "aruba_os"

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        enable_secret: str = "",
        timeout: int = 30,
    ) -> None:
        self.host       = host
        self._username  = username
        self._password  = password
        self._enable    = enable_secret or ""
        self._timeout   = timeout
        self._net       = None      # netmiko connection, set after login
        self.error: str = ""

    # ─── attributes the SwitchDriver protocol promises ───────────────────────

    @property
    def logged_in(self) -> bool:
        return self._net is not None

    # ─── lifecycle ──────────────────────────────────────────────────────────

    def login(self) -> bool:
        try:
            from netmiko import ConnectHandler          # lazy
        except ImportError as exc:
            self.error = (
                "netmiko not installed — pip3 install -r "
                "/opt/aruba-agent/requirements.txt "
                f"({type(exc).__name__}: {exc})"
            )
            log.warning(self.error)
            return False

        params = {
            "device_type": "hp_procurve",
            "host":        self.host,
            "username":    self._username,
            "password":    self._password,
            "timeout":     self._timeout,
            "fast_cli":    False,
        }
        if self._enable:
            params["secret"] = self._enable

        try:
            net = ConnectHandler(**params)
        except Exception as exc:
            self.error = _redact(f"{type(exc).__name__}: {exc}")
            log.debug("Aruba OS-S login failed for %s: %s", self.host, self.error)
            self._net = None
            return False

        # Escalate to manager mode when a secret is configured. Best
        # effort — if the account is already manager, enable() is a
        # harmless no-op; if it fails we keep the session and let the
        # first privileged command surface the real error.
        if self._enable:
            try:
                net.enable()
            except Exception as exc:
                log.debug("Aruba OS-S enable() on %s: %s", self.host, exc)

        self._net = net
        # ProCurve / Aruba OS-S session prep (terminal width / no page)
        # can leave a harmless "Invalid input: width" echo in the read
        # buffer on 6000/6100-class boxes. Flush it so the first real
        # command's output isn't contaminated (this bit save detection).
        try:
            net.clear_buffer()
        except Exception:
            pass
        return True

    def logout(self) -> None:
        if self._net is None:
            return
        try:
            self._net.disconnect()
        except Exception as exc:
            log.debug("Aruba OS-S logout error on %s: %s", self.host, exc)
        finally:
            self._net = None

    def __enter__(self) -> "ArubaOSDriver":
        self.login()
        return self

    def __exit__(self, *exc) -> None:
        self.logout()

    # ─── internal send helper ────────────────────────────────────────────────

    def _send(self, cmd: str, timing: bool = False, **kw) -> Optional[str]:
        """Run one command, tolerating netmiko version differences
        (older releases lack the ``read_timeout`` kwarg)."""
        if self._net is None:
            return None
        try:
            if timing:
                return self._net.send_command_timing(cmd)
            try:
                return self._net.send_command(cmd, **kw)
            except TypeError:
                kw.pop("read_timeout", None)
                return self._net.send_command(cmd, **kw)
        except Exception as exc:
            self.error = _redact(str(exc))
            return None

    # ─── health ─────────────────────────────────────────────────────────────

    def is_reachable(self) -> bool:
        if self._net is None:
            return False
        try:
            return bool(self._net.is_alive())
        except Exception as exc:
            self.error = _redact(str(exc))
            return False

    # ─── identity ───────────────────────────────────────────────────────────

    def get_hostname(self) -> Optional[str]:
        if self._net is None:
            return None
        try:
            prompt = self._net.find_prompt()
        except Exception as exc:
            self.error = _redact(str(exc))
            return None
        # ProCurve prompt looks like "HP-2530-8G-PoEP#" or "sw-name>"
        return (prompt or "").rstrip("#> ").strip() or None

    def get_facts(self) -> Optional[Facts]:
        return Facts(hostname=self.get_hostname() or "", vendor=self.vendor)

    # ─── configuration ──────────────────────────────────────────────────────

    def get_running_config(self) -> Optional[bytes]:
        """Pull running-config as bytes (matching the other drivers so
        backup.py doesn't branch). Configs can be long, so allow a
        generous read timeout."""
        out = self._send("show running-config", read_timeout=120)
        if out is None:
            if not self.error:
                self.error = "empty running-config"
            return None
        text = out.strip()
        return text.encode("utf-8") if text else None

    def save_running_to_startup(self) -> bool:
        """``write memory`` copies running-config → startup-config on
        ProCurve / Aruba OS-S. The "Copying configuration" spinner can
        run 10-20s, so use send_command (waits for the prompt) with a
        generous timeout rather than _timing, which would also scoop up
        stale session-prep output."""
        if self._net is None:
            return False
        out = self._send("write memory", read_timeout=120)
        if out is None:
            return False
        low = out.lower()
        if "success" in low:                       # 6000/6100 print "[Success]"
            return True
        # Older 2530/2930F are silent on success — only fail on a clear
        # rejection of the write-memory command itself.
        if any(w in low for w in ("invalid input", "unknown command",
                                   "incomplete", "not found")):
            self.error = " ".join(out.split())[:200]
            return False
        return True

    # ─── operational ────────────────────────────────────────────────────────

    def cli(self, cmd: str) -> Optional[str]:
        return self._send(cmd, read_timeout=60)

    def get_arp_table(self) -> List[ArpEntry]:
        """Parse ``show arp``. Best-effort — returns [] on any trouble
        rather than raising, since backup doesn't depend on it."""
        out = self._send("show arp", read_timeout=60)
        if not out:
            return []
        entries: List[ArpEntry] = []
        for line in out.splitlines():
            parts = line.split()
            # ProCurve rows look like:
            #   10.80.9.1   001122-334455  dynamic  5
            if len(parts) >= 2 and parts[0].count(".") == 3 and "-" in parts[1]:
                entries.append(ArpEntry(
                    ip        = parts[0],
                    mac       = parts[1],
                    interface = parts[3] if len(parts) >= 4 else "",
                ))
        return entries
