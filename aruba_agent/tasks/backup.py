"""
Config Backup Task — ported from Aruba_Switch_Backup.py.

Loops through ip_list, saves running-config → startup-config on each switch,
downloads the binary, stores it locally with rolling retention, then emails
a summary report and updates AgentState.
"""

from __future__ import annotations

import configparser
import glob
import logging
import os
from datetime import datetime
from typing import List

from aruba_agent.drivers   import driver_for
from aruba_agent.notifier  import EmailNotifier
from aruba_agent.state     import AgentState

log = logging.getLogger(__name__)


class BackupTask:
    def __init__(
        self,
        cfg: configparser.ConfigParser,
        notifier: EmailNotifier,
        state: AgentState,
    ) -> None:
        b  = cfg["backup"]      if "backup"      in cfg else {}
        cr = cfg["credentials"] if "credentials" in cfg else {}
        self.ip_list_path = b.get("ip_list",     "/etc/aruba-agent/ip_list.txt")
        self.backup_path  = b.get("backup_path", "/var/lib/aruba-agent/backups")
        self.retention    = int(b.get("retention_days", "7"))
        self.username     = cr.get("username", "admin")
        self.password     = cr.get("password", "")
        self.api_version  = b.get("api_version") or None   # None → auto-detect

        # Per-vendor overrides — only Cisco needs separate creds today.
        # Blank values fall through to the default username/password
        # above, so a single-credential shop doesn't need to fill them
        # in twice.
        cc = cfg["credentials.cisco"] if "credentials.cisco" in cfg else {}
        self.cisco_username = (cc.get("username", "") or "").strip()
        self.cisco_password = cc.get("password", "")
        self.cisco_enable   = cc.get("enable_secret", "")
        self.cisco_napalm   = (cc.get("napalm_driver", "ios") or "ios").strip()

        self.notifier     = notifier
        self.state        = state

    def _load_ips(self) -> List[str]:
        try:
            with open(self.ip_list_path) as f:
                return [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            log.error("Backup: ip_list not found at %s", self.ip_list_path)
            return []

    def _cleanup(self, host_dir: str, hostname: str) -> None:
        files = sorted(
            glob.glob(os.path.join(host_dir, f"{hostname}-startup-config-*.cfg")),
            key=os.path.getmtime,
        )
        for old in files[: -self.retention]:
            try:
                os.remove(old)
                log.info("Backup: removed old file %s", os.path.basename(old))
            except OSError as exc:
                log.warning("Backup: could not remove %s: %s", old, exc)

    def run(self) -> None:
        log.info("Backup task started")
        ips = self._load_ips()
        if not ips:
            return

        success: List[dict] = []
        failed:  List[dict] = []

        for ip in ips:
            hostname = "N/A"
            # Per-host vendor lookup. The C3 detector populates
            # SwitchState.vendor on the first reachable SNMPv3 poll;
            # we use that here so Aruba switches go through the
            # AOS-CX REST path (unchanged) and Cisco switches go
            # through NAPALM via SSH automatically. Empty / unknown
            # vendors default to the AOS-CX driver, preserving v2.x
            # behavior.
            vendor = self.state.get_vendor_for_host(ip) or None
            try:
                with driver_for(
                    ip, self.username, self.password,
                    preferred_version  = self.api_version,
                    vendor_hint        = vendor,
                    cisco_username     = self.cisco_username,
                    cisco_password     = self.cisco_password,
                    cisco_enable       = self.cisco_enable,
                    cisco_napalm_driver= self.cisco_napalm,
                ) as drv:
                    if not drv.logged_in:
                        failed.append({"ip": ip, "hostname": hostname,
                                       "issue": f"Login failed ({drv.vendor}): "
                                                f"{drv.error}"})
                        continue

                    hostname = drv.get_hostname() or "unknown"

                    if not drv.save_running_to_startup():
                        failed.append({"ip": ip, "hostname": hostname,
                                       "issue": f"Save running→startup failed "
                                                f"({drv.vendor}): {drv.error}"})
                        continue

                    data = drv.get_running_config()
                    if not data:
                        failed.append({"ip": ip, "hostname": hostname,
                                       "issue": f"Config download failed "
                                                f"({drv.vendor}): {drv.error}"})
                        continue

                # Write outside the with-block so logout happens first
                host_dir = os.path.join(self.backup_path, hostname)
                os.makedirs(host_dir, exist_ok=True)
                ts    = datetime.now().strftime("%Y-%m-%d_%H%M%S")
                fpath = os.path.join(host_dir, f"{hostname}-startup-config-{ts}.cfg")
                with open(fpath, "wb") as f:
                    f.write(data)
                self._cleanup(host_dir, hostname)
                success.append({"ip": ip, "hostname": hostname})
                log.info("Backup OK: %s (%s)", hostname, ip)

            except Exception as exc:
                failed.append({"ip": ip, "hostname": hostname, "issue": str(exc)})
                log.error("Backup error for %s: %s", ip, exc)

        self.state.set_backup_result(len(success), len(failed), failed)
        self._send_report(success, failed)
        log.info("Backup task done: %d ok, %d failed", len(success), len(failed))

    def _send_report(self, success: List[dict], failed: List[dict]) -> None:
        now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body = (
            f"Aruba CX Config Backup — {now}\n"
            f"Total: {len(success)+len(failed)}  |  OK: {len(success)}  |  Failed: {len(failed)}\n"
        )
        if success:
            body += "\nSUCCESSFUL:\n"
            body += "\n".join(f"  {s['ip']:16s}  {s['hostname']}" for s in success)
        if failed:
            body += "\n\nFAILED:\n"
            body += "\n".join(
                f"  {f['ip']:16s}  {f['hostname']:24s}  {f['issue']}" for f in failed
            )
        self.notifier.send(
            f"[Aruba] Config Backup Report — {datetime.now().strftime('%Y-%m-%d')}",
            body,
        )
