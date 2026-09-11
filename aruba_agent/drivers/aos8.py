"""
Aruba AOS-8 Mobility driver (controllers, conductors, VPN gateways).

Covers the Mobility Conductor (ArubaMM), 9240 Mobility Controllers, and
the 9004 standalone/VPN controller — all running "HPE Aruba Networking
Wireless Operating System / AOS-8". These are managed over SSH CLI (no
AOS-CX REST), so this driver uses netmiko's ``aruba_os`` device type,
which knows the ``(host) #`` prompt and ``no paging`` behaviour of the
controller CLI.

This is deliberately SEPARATE from the ArubaOSDriver (netmiko
``hp_procurve``), which handles the unrelated Aruba OS-S / ProCurve
*switches*. The vendor keys differ too: this driver is ``aruba_aos8``.

Backup
------
Two modes (see ``get_running_config`` / backup_mode):
  * "flash"          — run ``backup flash`` then pull the resulting
                       flashbackup.tar.gz off the box (full backup:
                       config, licenses, certs). Falls back to running
                       config text if the archive can't be retrieved.
  * "running-config" — just capture ``show running-config`` text.

netmiko (and paramiko, for the flash pull) are imported lazily so a
missing dep degrades to a clear error rather than breaking startup.
Never raises on transport errors — returns None/False and sets
self.error, matching the SwitchDriver protocol.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from aruba_agent.drivers.base import ArpEntry, Facts
from aruba_agent.secrets_store import redact as _redact

log = logging.getLogger(__name__)

# Candidate remote paths for the flash backup archive (varies by version).
_FLASH_PATHS = ("/flash/flashbackup.tar.gz", "flash/flashbackup.tar.gz",
                "flashbackup.tar.gz")


class AOS8Driver:
    """SwitchDriver implementation for AOS-8 Mobility controllers over SSH."""

    vendor = "aruba_aos8"

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        enable_secret: str = "",
        timeout: int = 30,
        backup_mode: str = "flash",     # "flash" | "running-config"
    ) -> None:
        self.host        = host
        self._username   = username
        self._password   = password
        self._enable     = enable_secret or ""
        self._timeout    = timeout
        self._backup_mode = (backup_mode or "flash").strip().lower()
        self._net        = None
        self.error: str  = ""

    @property
    def logged_in(self) -> bool:
        return self._net is not None

    # ── lifecycle ─────────────────────────────────────────────────────────

    def login(self) -> bool:
        try:
            from netmiko import ConnectHandler          # lazy
        except ImportError as exc:
            self.error = (
                "netmiko not installed — pip3 install -r "
                f"/opt/aruba-agent/requirements.txt ({type(exc).__name__}: {exc})"
            )
            log.warning(self.error)
            return False

        params = {
            "device_type": "aruba_os",
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
            log.debug("AOS-8 login failed for %s: %s", self.host, self.error)
            self._net = None
            return False

        if self._enable:
            try:
                net.enable()
            except Exception as exc:
                log.debug("AOS-8 enable() on %s: %s", self.host, exc)
        try:
            net.clear_buffer()
        except Exception:
            pass
        self._net = net
        return True

    def logout(self) -> None:
        if self._net is None:
            return
        try:
            self._net.disconnect()
        except Exception as exc:
            log.debug("AOS-8 logout error on %s: %s", self.host, exc)
        finally:
            self._net = None

    def __enter__(self) -> "AOS8Driver":
        self.login()
        return self

    def __exit__(self, *exc) -> None:
        self.logout()

    # ── send helper ───────────────────────────────────────────────────────

    def _send(self, cmd: str, **kw) -> Optional[str]:
        if self._net is None:
            return None
        try:
            try:
                return self._net.send_command(cmd, **kw)
            except TypeError:
                kw.pop("read_timeout", None)
                return self._net.send_command(cmd, **kw)
        except Exception as exc:
            self.error = _redact(str(exc))
            return None

    # ── health / identity ─────────────────────────────────────────────────

    def is_reachable(self) -> bool:
        if self._net is None:
            return False
        try:
            return bool(self._net.is_alive())
        except Exception as exc:
            self.error = _redact(str(exc))
            return False

    def get_hostname(self) -> Optional[str]:
        if self._net is None:
            return None
        try:
            prompt = self._net.find_prompt()
        except Exception as exc:
            self.error = _redact(str(exc))
            return None
        # AOS-8 prompt: "(hostname) #" or "(hostname) [mynode] #"
        p = (prompt or "").strip()
        if p.startswith("(") and ")" in p:
            return p[1:p.index(")")].strip() or None
        return p.rstrip("#> ").strip() or None

    def get_facts(self) -> Optional[Facts]:
        return Facts(hostname=self.get_hostname() or "", vendor=self.vendor)

    def cli(self, cmd: str) -> Optional[str]:
        """Run a show command and return its text (used by the web-server
        health job)."""
        return self._send(cmd, read_timeout=60)

    # ── configuration / backup ────────────────────────────────────────────

    def save_running_to_startup(self) -> bool:
        """AOS-8 persists with ``write memory``."""
        if self._net is None:
            return False
        out = self._send("write memory", read_timeout=90)
        if out is None:
            return False
        low = out.lower()
        if any(w in low for w in ("error", "invalid", "failure", "cannot")):
            self.error = " ".join(out.split())[:200]
            return False
        return True

    def _running_config_bytes(self) -> Optional[bytes]:
        out = self._send("show running-config", read_timeout=180)
        if out is None:
            if not self.error:
                self.error = "empty running-config"
            return None
        text = out.strip()
        return text.encode("utf-8") if text else None

    def _pull_flash_backup(self) -> Optional[bytes]:
        """Run ``backup flash`` and retrieve flashbackup.tar.gz via SFTP/SCP.
        Returns the archive bytes, or None if the box won't hand it over."""
        # 1. create the archive
        out = self._send("backup flash", read_timeout=180)
        if out is not None and "error" in out.lower() and "success" not in out.lower():
            self.error = " ".join(out.split())[:200]
            # keep going — some versions are terse; the file may still exist
        # 2. try to retrieve it over a fresh paramiko session (SFTP first,
        #    then the scp module if present).
        try:
            import paramiko                              # lazy
        except ImportError as exc:
            self.error = f"paramiko not available for flash pull ({exc})"
            return None

        cli = None
        try:
            cli = paramiko.SSHClient()
            cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            cli.connect(self.host, username=self._username, password=self._password,
                        timeout=self._timeout, look_for_keys=False, allow_agent=False)
            # SFTP get
            try:
                sftp = cli.open_sftp()
                for rp in _FLASH_PATHS:
                    try:
                        import io
                        buf = io.BytesIO()
                        sftp.getfo(rp, buf)
                        data = buf.getvalue()
                        if data:
                            log.info("AOS-8 %s: pulled flash backup via SFTP (%d bytes)",
                                     self.host, len(data))
                            return data
                    except Exception:
                        continue
            except Exception as exc:
                log.debug("AOS-8 %s: SFTP unavailable (%s) — trying scp", self.host, exc)
            # scp module fallback
            try:
                from scp import SCPClient                 # optional dep
                import io
                for rp in _FLASH_PATHS:
                    try:
                        buf = io.BytesIO()
                        with SCPClient(cli.get_transport()) as scp:
                            scp.getfo(rp, buf)
                        data = buf.getvalue()
                        if data:
                            log.info("AOS-8 %s: pulled flash backup via SCP (%d bytes)",
                                     self.host, len(data))
                            return data
                    except Exception:
                        continue
            except ImportError:
                pass
        except Exception as exc:
            self.error = _redact(f"flash pull failed: {type(exc).__name__}: {exc}")
        finally:
            if cli is not None:
                try:
                    cli.close()
                except Exception:
                    pass
        if not self.error:
            self.error = "could not retrieve flashbackup.tar.gz (SFTP/SCP unavailable)"
        return None

    def get_running_config(self) -> Optional[bytes]:
        """Backup entry point. In flash mode, return the flashbackup.tar.gz
        bytes; if that can't be retrieved, fall back to running-config text
        so a backup is still captured. In running-config mode, just the
        config text."""
        if self._backup_mode == "flash":
            data = self._pull_flash_backup()
            if data:
                return data
            log.warning("AOS-8 %s: flash backup unavailable (%s) — falling back "
                        "to show running-config", self.host, self.error or "?")
            self.error = ""   # clear so the fallback's own errors surface
        return self._running_config_bytes()

    def get_arp_table(self) -> List[ArpEntry]:
        # Not used for controllers; keep the protocol satisfied.
        return []
