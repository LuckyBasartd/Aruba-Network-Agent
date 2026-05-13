"""
ARP Discovery Task — merged from sh_ip_arp.py, mh_ip_arp.py, kipj_ip_arp.py.

One ArpDiscoveryTask per location (config section [arp.<name>]).
For each location:
  1. nmap ping-sweep all configured subnets → IP→DNS map
  2. Query each router ARP table via AOS-CX CLI API ('show arp')
  3. Deduplicate, filter, write timestamped CSV to output_dir
"""

from __future__ import annotations

import configparser
import csv
import glob
import ipaddress
import logging
import os
import re
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

from aruba_agent.drivers       import driver_for
from aruba_agent.secrets_store import decrypt as _decrypt
from aruba_agent.state         import AgentState

log = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$")

# AOS-CX show-arp's last column is one of these state words. We use it
# to tell whether parts[3] is the physical port or the state — on
# permanent / broadcast entries the physical port is omitted and the
# state shifts left by one column.
_ARP_STATES = frozenset({
    "reachable", "permanent", "incomplete", "stale",
    "delay",     "probe",     "failed",     "static",
})


class ArpDiscoveryTask:
    def __init__(
        self,
        name: str,
        sec: configparser.SectionProxy,
        creds: configparser.SectionProxy,
        state: AgentState,
        cisco_creds:  "Optional[configparser.SectionProxy]" = None,
        arista_creds: "Optional[configparser.SectionProxy]" = None,
    ) -> None:
        self.name       = name
        self.router_ips = [r.strip() for r in sec.get("routers", "").split(",") if r.strip()]
        self.ip_list    = sec.get("ip_list", "")
        self.output_dir = sec.get("output_dir", f"/var/lib/aruba-agent/arp/{name}")
        # v3.0.1: rolling retention. CSVs older than retention_days get
        # pruned at the end of each run. Default 30 days — long enough
        # for the operator to do back-references when troubleshooting
        # a "where did this device live last week" question, short
        # enough that the directory doesn't grow forever. Set 0 to
        # disable pruning.
        try:
            self.retention = int(sec.get("retention_days", "30") or "30")
        except (TypeError, ValueError):
            self.retention = 30
        self.username   = creds.get("username", "admin")
        # Passwords / enable secrets are decrypted at read time so the
        # driver layer sees cleartext as it always has.
        self.password   = _decrypt(creds.get("password", ""))
        self.state      = state

        # Per-vendor credentials. Blank values fall through to the
        # default username/password above.
        cc = cisco_creds or {}
        self.cisco_username = (cc.get("username", "") or "").strip()
        self.cisco_password = _decrypt(cc.get("password", ""))
        self.cisco_enable   = _decrypt(cc.get("enable_secret", ""))
        self.cisco_napalm   = (cc.get("napalm_driver", "ios") or "ios").strip()
        # v3.0.3: optional SSH key for Cisco (NAPALM netmiko).
        self.cisco_key_file = (cc.get("key_file", "") or "").strip()

        ac = arista_creds or {}
        self.arista_username = (ac.get("username", "") or "").strip()
        self.arista_password = _decrypt(ac.get("password", ""))
        self.arista_enable   = _decrypt(ac.get("enable_password", ""))
        self.arista_transport = (ac.get("transport", "https") or "https").strip()
        try:
            self.arista_port = int(ac.get("port", "")) if (ac.get("port", "") or "").strip() else None
        except ValueError:
            self.arista_port = None

    def _load_subnets(self) -> List[str]:
        if not self.ip_list or not os.path.exists(self.ip_list):
            log.error("ARP[%s]: subnet file not found: %s", self.name, self.ip_list)
            return []
        with open(self.ip_list) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]

    def _nmap_scan(self, subnets: List[str]) -> Dict[str, str]:
        ip_to_dns: Dict[str, str] = {}
        for subnet in subnets:
            try:
                result = subprocess.run(
                    ["nmap", "-sn", subnet],
                    capture_output=True, text=True, check=True, timeout=120,
                )
                for line in result.stdout.splitlines():
                    if not line.startswith("Nmap scan report for"):
                        continue
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    host_info = " ".join(parts[4:])
                    if "(" in host_info and ")" in host_info:
                        dns = host_info.split(" (")[0]
                        ip  = host_info.split("(")[1].rstrip(")")
                    else:
                        dns, ip = "", host_info
                    ip_to_dns[ip.strip()] = dns
            except Exception as exc:
                log.error("ARP[%s]: nmap error on %s: %s", self.name, subnet, exc)
        return ip_to_dns

    def _fetch_arp(self, router_ip: str) -> List[dict]:
        # Per-host vendor lookup so a Cisco router goes through NAPALM/SSH
        # while Aruba routers keep using AOS-CX REST. Empty / unknown
        # vendor → AOS-CX driver (the v2.x default).
        vendor = self.state.get_vendor_for_host(router_ip) or None
        with driver_for(
            router_ip, self.username, self.password,
            vendor_hint             = vendor,
            cisco_username          = self.cisco_username,
            cisco_password          = self.cisco_password,
            cisco_enable            = self.cisco_enable,
            cisco_napalm_driver     = self.cisco_napalm,
            cisco_key_file          = self.cisco_key_file,
            arista_username         = self.arista_username,
            arista_password         = self.arista_password,
            arista_enable_password  = self.arista_enable,
            arista_transport        = self.arista_transport,
            arista_port             = self.arista_port,
        ) as drv:
            if not drv.logged_in:
                log.error("ARP[%s]: login failed for %s (%s): %s",
                          self.name, router_ip, drv.vendor, drv.error)
                return []
            # Aruba `show arp` and Cisco `show arp` both produce
            # textual output that the existing parser handles. If we
            # ever need true vendor-neutral parsing, drv.get_arp_table()
            # is available on every driver — but the CSV downstream
            # expects (ip, mac, type, port) and the current parser
            # produces exactly that on both vendors.
            text = drv.cli("show arp")
        if not text:
            log.error("ARP[%s]: no output from %s", self.name, router_ip)
            return []
        return self._parse_arp(text)

    def _parse_arp(self, text: str) -> List[dict]:
        """
        Parse `show arp` output from AOS-CX. Modern layout:

            IPv4 Address     MAC                Port     Physical Port    State
            -----------------------------------------------------------------------
            10.40.176.120    d0:8e:79:03:e0:a2  vlan218  lag13            reachable
            10.41.17.255     FF:FF:FF:FF:FF:FF  vlan236                   permanent

        Permanent / broadcast entries omit the physical-port column,
        so parts[3] becomes the state word instead. We detect that
        and treat physical port as empty in those rows. Broadcast
        MACs are dropped entirely — they're not real hosts.

        Returns a list of {ip, mac, type, port} dicts, where 'type'
        carries the VLAN name (the most useful piece of grouping
        info for ARP-driven device inventory).
        """
        entries = []
        for line in text.strip().splitlines():
            # First field must be an IPv4 — skips headers, dashes, blanks
            if not re.match(r"^\s*\d+\.\d+\.\d+\.\d+\b", line):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue

            ip, mac = parts[0], parts[1]
            if not _MAC_RE.match(mac):
                continue
            # Drop broadcast / permanent FF:FF entries — not real hosts
            if mac.upper() == "FF:FF:FF:FF:FF:FF":
                continue

            vlan = parts[2]
            # parts[3] is normally the physical port (lag5 / 1/1/24 / etc).
            # On entries without one, it's actually the state word —
            # detect by lowercase membership in the known state set.
            port = ""
            if len(parts) >= 4 and parts[3].lower() not in _ARP_STATES:
                port = parts[3]

            entries.append({
                "ip":   ip,
                "mac":  mac,
                "type": vlan,
                "port": port,
            })
        return entries

    def _write_csv(
        self,
        entries: List[dict],
        ip_to_dns: Dict[str, str],
        subnets: List[str],
    ) -> None:
        subnet_objs = []
        for s in subnets:
            try:
                subnet_objs.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                pass

        unique = {e["ip"]: e for e in entries}   # deduplicate by IP
        rows: List[list] = []
        for ip, data in unique.items():
            try:
                last = int(ip.split(".")[-1])
            except ValueError:
                continue
            if last in (1, 2, 3, 255):
                continue
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if not any(ip_obj in net for net in subnet_objs):
                continue
            rows.append([ip, data["mac"], data["type"], data["port"], ip_to_dns.get(ip, "")])

        if not rows:
            log.warning("ARP[%s]: no entries after filtering", self.name)
            return

        os.makedirs(self.output_dir, exist_ok=True)
        ts    = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        fpath = os.path.join(self.output_dir, f"arp_scan_{ts}.csv")
        with open(fpath, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["IP Address", "MAC Address", "Type", "Port", "DNS"])
            w.writerows(rows)
        log.info("ARP[%s]: wrote %d entries → %s", self.name, len(rows), fpath)

    def _cleanup(self) -> None:
        """
        Prune arp_scan_*.csv files older than ``retention_days`` from
        ``output_dir``. Mirrors BackupTask._cleanup: keep the N newest
        and delete everything older. retention=0 means keep forever.
        """
        if self.retention <= 0:
            return
        try:
            files = sorted(
                glob.glob(os.path.join(self.output_dir, "arp_scan_*.csv")),
                key=os.path.getmtime,
            )
        except OSError as exc:
            log.warning("ARP[%s]: could not list %s for cleanup: %s",
                        self.name, self.output_dir, exc)
            return
        # files is now oldest → newest; keep the last `retention` entries.
        # We retain by COUNT here (one CSV per run), which is equivalent
        # to "retention_days days of history" when the task runs daily,
        # and degrades gracefully when it runs more often.
        for old in files[: -self.retention]:
            try:
                os.remove(old)
                log.info("ARP[%s]: removed old CSV %s",
                         self.name, os.path.basename(old))
            except OSError as exc:
                log.warning("ARP[%s]: could not remove %s: %s",
                            self.name, old, exc)

    def run(self) -> None:
        log.info("ARP discovery started: %s", self.name)
        subnets = self._load_subnets()
        if not subnets or not self.router_ips:
            log.warning("ARP[%s]: missing subnets or router IPs — skipping", self.name)
            return

        ip_to_dns: Dict[str, str] = self._nmap_scan(subnets)
        all_entries: List[dict]   = []
        for router in self.router_ips:
            # v3.0.3: ARP discovery needs management-plane access to
            # the router. Skip any router the operator has flagged
            # icmp-only or snmp_ro — those won't accept "show arp".
            mode = self.state.get_mode_for_host(router)
            if mode in ("icmp", "snmp_ro"):
                log.info("ARP[%s]: skipping router %s — monitor_mode=%s",
                         self.name, router, mode)
                continue
            all_entries.extend(self._fetch_arp(router))

        if all_entries:
            self._write_csv(all_entries, ip_to_dns, subnets)
        else:
            log.warning("ARP[%s]: no ARP data from any router", self.name)

        # Retention pass: drop CSVs older than retention_days even when
        # this particular run wrote nothing — operators expect history
        # to age out regardless of fresh data.
        self._cleanup()

        self.state.set_arp_last_run(self.name)
        log.info("ARP discovery done: %s", self.name)
