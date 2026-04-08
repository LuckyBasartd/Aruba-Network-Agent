"""
Network Scanner Task — ported from network_scanner.py.

ICMP-scans configured subnets via Scapy, compares against the last known
device CSV, alerts on new devices, and regenerates ip_list.txt for backup.

Requires: scapy  +  CAP_NET_RAW capability (or root).
"""

from __future__ import annotations

import configparser
import csv
import ipaddress
import logging
import os
import socket
from typing import TYPE_CHECKING, Dict, List, Optional

from aruba_agent.notifier import EmailNotifier
from aruba_agent.state    import AgentState

if TYPE_CHECKING:
    from aruba_agent.monitors.switch_poller import SwitchMonitorManager

log = logging.getLogger(__name__)


class NetworkScannerTask:
    def __init__(
        self,
        cfg: configparser.ConfigParser,
        notifier: EmailNotifier,
        state: AgentState,
        monitor_manager: "Optional[SwitchMonitorManager]" = None,
    ) -> None:
        s = cfg["scanner"] if "scanner" in cfg else {}
        self.subnets          = [x.strip() for x in s.get("subnets", "").split(",") if x.strip()]
        self.exclude_suffixes = tuple(
            x.strip() for x in s.get("exclude_suffixes", "1,2,3,255").split(",") if x.strip()
        )
        self.filter_keywords  = [
            x.strip() for x in s.get("filter_keywords", "6100,6300,Aruba").split(",") if x.strip()
        ]
        self.device_file     = s.get("device_file",    "/var/lib/aruba-agent/network_devices.csv")
        self.ip_list_output  = s.get("ip_list_output", "/var/lib/aruba-agent/ip_list.txt")
        self.icmp_timeout    = int(s.get("icmp_timeout", "3"))
        self.notifier        = notifier
        self.monitor_manager = monitor_manager   # injected so scanner can register new switches
        self.state          = state

    def _scan(self) -> Dict[str, str]:
        try:
            from scapy.all import IP, ICMP, sr  # type: ignore[import]
        except ImportError:
            log.error("Scanner: scapy not installed — run: pip install scapy")
            return {}

        devices: Dict[str, str] = {}
        for subnet in self.subnets:
            try:
                net     = ipaddress.ip_network(subnet, strict=False)
                targets = [
                    str(ip) for ip in net.hosts()
                    if str(ip).split(".")[-1] not in self.exclude_suffixes
                ]
                if not targets:
                    continue
                log.info("Scanner: pinging %d hosts in %s", len(targets), subnet)
                answered, _ = sr(
                    IP(dst=targets) / ICMP(),
                    timeout=self.icmp_timeout,
                    verbose=0,
                )
                for sent, received in answered:
                    if received.haslayer(ICMP) and received.getlayer(ICMP).type == 0:
                        ip = sent.dst
                        if ip not in devices:
                            try:
                                name = socket.gethostbyaddr(ip)[0]
                            except socket.herror:
                                name = "N/A"
                            devices[ip] = name
            except Exception as exc:
                log.error("Scanner: error on %s: %s", subnet, exc)

        log.info("Scanner: found %d devices", len(devices))
        return devices

    def _load_existing(self) -> Dict[str, str]:
        if not os.path.exists(self.device_file):
            return {}
        try:
            with open(self.device_file, newline="") as f:
                reader = csv.reader(f)
                next(reader, None)
                return {row[0]: row[1] for row in reader if row}
        except Exception as exc:
            log.error("Scanner: could not read device file: %s", exc)
            return {}

    def _save_devices(self, devices: Dict[str, str]) -> None:
        os.makedirs(os.path.dirname(self.device_file) or ".", exist_ok=True)
        try:
            sorted_devs = sorted(devices.items(), key=lambda x: ipaddress.ip_address(x[0]))
        except Exception:
            sorted_devs = sorted(devices.items())
        with open(self.device_file, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["IP_Address", "DNS_Name"])
            w.writerows(sorted_devs)

    def _write_ip_list(self, devices: Dict[str, str]) -> List[str]:
        matching = sorted(
            [ip for ip, name in devices.items()
             if any(kw in name for kw in self.filter_keywords)],
            key=lambda ip: ipaddress.ip_address(ip),
        )
        os.makedirs(os.path.dirname(self.ip_list_output) or ".", exist_ok=True)
        with open(self.ip_list_output, "w") as f:
            f.writelines(ip + "\n" for ip in matching)
        log.info("Scanner: wrote %d Aruba IPs to %s", len(matching), self.ip_list_output)
        return matching

    def run(self) -> None:
        if not self.subnets:
            log.warning("Scanner: no subnets configured — skipping")
            return
        log.info("Network scanner task started")
        existing = self._load_existing()
        current  = self._scan()
        new_devs = {ip: current[ip] for ip in set(current) - set(existing)}

        if new_devs:
            log.info("Scanner: %d new device(s) found", len(new_devs))
            try:
                sorted_new: List = sorted(
                    new_devs.items(), key=lambda x: ipaddress.ip_address(x[0])
                )
            except Exception:
                sorted_new = sorted(new_devs.items())
            body = "New devices discovered on the network:\n\n" + "\n".join(
                f"  {ip:16s}  {name}" for ip, name in sorted_new
            )
            self.notifier.send("[Aruba] New Devices Discovered", body)

        self._save_devices(current)
        switch_ips = self._write_ip_list(current)

        # Register every discovered switch with the reachability monitor
        if self.monitor_manager is not None and switch_ips:
            log.info("Scanner: syncing %d switch IPs to monitor manager", len(switch_ips))
            self.monitor_manager.sync(switch_ips)

        # Update shared state for the web UI
        self.state.set_device_inventory(
            [{"ip": ip, "name": name} for ip, name in current.items()]
        )
        log.info("Network scanner task done")
