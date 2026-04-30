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
import ipaddress
import logging
import os
import re
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

from aruba_agent.drivers   import driver_for
from aruba_agent.state     import AgentState

log = logging.getLogger(__name__)

_VLAN_RE = re.compile(r"^vlan\d+$", re.IGNORECASE)


class ArpDiscoveryTask:
    def __init__(
        self,
        name: str,
        sec: configparser.SectionProxy,
        creds: configparser.SectionProxy,
        state: AgentState,
        cisco_creds: "Optional[configparser.SectionProxy]" = None,
    ) -> None:
        self.name       = name
        self.router_ips = [r.strip() for r in sec.get("routers", "").split(",") if r.strip()]
        self.ip_list    = sec.get("ip_list", "")
        self.output_dir = sec.get("output_dir", f"/var/lib/aruba-agent/arp/{name}")
        self.username   = creds.get("username", "admin")
        self.password   = creds.get("password", "")
        self.state      = state

        # Cisco-specific credentials for routers classified as
        # cisco_ios. Blank values fall through to the default
        # username/password above.
        cc = cisco_creds or {}
        self.cisco_username = (cc.get("username", "") or "").strip()
        self.cisco_password = cc.get("password", "")
        self.cisco_enable   = cc.get("enable_secret", "")
        self.cisco_napalm   = (cc.get("napalm_driver", "ios") or "ios").strip()

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
            vendor_hint        = vendor,
            cisco_username     = self.cisco_username,
            cisco_password     = self.cisco_password,
            cisco_enable       = self.cisco_enable,
            cisco_napalm_driver= self.cisco_napalm,
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
        entries = []
        for line in text.strip().splitlines():
            if not re.match(r"\d+\.\d+\.\d+\.\d+", line):
                continue
            parts = line.split()
            if len(parts) >= 4 and not _VLAN_RE.match(parts[2]):
                entries.append({
                    "ip": parts[0], "mac": parts[1],
                    "type": parts[2], "port": parts[3],
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

    def run(self) -> None:
        log.info("ARP discovery started: %s", self.name)
        subnets = self._load_subnets()
        if not subnets or not self.router_ips:
            log.warning("ARP[%s]: missing subnets or router IPs — skipping", self.name)
            return

        ip_to_dns: Dict[str, str] = self._nmap_scan(subnets)
        all_entries: List[dict]   = []
        for router in self.router_ips:
            all_entries.extend(self._fetch_arp(router))

        if all_entries:
            self._write_csv(all_entries, ip_to_dns, subnets)
        else:
            log.warning("ARP[%s]: no ARP data from any router", self.name)

        self.state.set_arp_last_run(self.name)
        log.info("ARP discovery done: %s", self.name)
