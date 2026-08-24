"""
Network Scanner Task — ported from network_scanner.py.

ICMP-scans configured subnets via the OS ``ping`` (kernel routing),
compares against the last known
device CSV, alerts on new devices, and regenerates ip_list.txt for backup.

Discovery decision tree for each pinged host
--------------------------------------------
1. Reverse-DNS lookup → name (or "N/A" on failure).
2. Fast path: if the name contains any of [scanner].filter_keywords,
   include it in ip_list.txt.
3. Slow path (verify_via_api, default on): for everything that ping'd but
   *failed* the keyword filter, attempt an AOS-CX REST API login. If
   the login succeeds, it's an Aruba switch — include it. Cisco and
   other non-Aruba gear fail the login and stay excluded.

The slow path exists because the keyword filter silently drops Aruba
switches with missing PTR records or non-matching naming conventions
(6200/6400/8325/2930F units, hand-named stacks, etc.).

Requires: /usr/bin/ping (unprivileged ping or CAP_NET_RAW). The OS ping
respects the kernel routing table, so routed subnets resolve correctly —
unlike the old scapy raw sweep, which broadcast and missed whole subnets.
"""

from __future__ import annotations

import configparser
import csv
import ipaddress
import logging
import os
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from aruba_agent.drivers       import driver_for
from aruba_agent.notifier      import EmailNotifier
from aruba_agent.secrets_store import decrypt as _decrypt
from aruba_agent.state         import AgentState

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

        # Coverage safeguard: a scan that suddenly discovers far fewer
        # switches than last time almost always means a discovery regression
        # (routing/DNS/credentials), not that switches vanished. Alert, and
        # with coverage_guard on, keep the previous ip_list rather than
        # letting monitoring/backup coverage silently collapse.
        self.coverage_drop_pct = int(s.get("coverage_drop_alert_pct", "25"))
        self.coverage_guard    = (
            s.get("coverage_guard", "true").strip().lower() in ("1", "true", "yes", "on")
        )

        # AOS-CX REST verification — recovers Aruba switches whose DNS names
        # don't match filter_keywords. Off only if the operator explicitly
        # disables it or no credentials are configured.
        self.verify_via_api = (
            s.get("verify_via_api", "true").strip().lower() in ("1", "true", "yes", "on")
        )
        self.api_workers = int(s.get("api_workers", "16"))
        creds = cfg["credentials"] if "credentials" in cfg else {}
        self._api_user = creds.get("username", "")
        # Decrypt at read time — cleartext passes through unchanged.
        self._api_pass = _decrypt(creds.get("password", ""))
        if self.verify_via_api and not (self._api_user and self._api_pass):
            log.warning(
                "Scanner: verify_via_api is enabled but [credentials] is empty — "
                "REST probe will be skipped."
            )
            self.verify_via_api = False

        self.notifier        = notifier
        self.monitor_manager = monitor_manager   # injected so scanner can register new switches
        self.state          = state

    def _ping_one(self, ip: str) -> Optional[str]:
        """One OS ICMP echo (kernel routing). Returns ip if alive, else None.
        Uses the same /usr/bin/ping path the poller uses — this is what
        makes routed subnets work, unlike the old scapy raw sweep which
        couldn't resolve next-hops and silently missed whole subnets."""
        try:
            r = subprocess.run(
                ["ping", "-n", "-c", "1", "-W", str(self.icmp_timeout), ip],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.icmp_timeout + 2,
            )
            return ip if r.returncode == 0 else None
        except (FileNotFoundError, subprocess.SubprocessError):
            return None

    def _scan(self) -> Dict[str, str]:
        """Liveness sweep of every configured subnet via the OS ``ping``,
        concurrently. Replaces the previous scapy raw sweep, which relied
        on scapy resolving the next-hop MAC itself and came back empty for
        routed subnets (the ``Using broadcast`` warnings) — silently
        dropping whole subnets of switches from monitoring and backups."""
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
                workers = min(128, max(1, len(targets)))
                with ThreadPoolExecutor(max_workers=workers,
                                        thread_name_prefix="scan-ping") as ex:
                    for ip in ex.map(self._ping_one, targets):
                        if ip and ip not in devices:
                            try:
                                name = socket.gethostbyaddr(ip)[0]
                            except (socket.herror, socket.gaierror):
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

    def _probe_one(self, ip: str) -> Optional[Tuple[str, str]]:
        """
        Attempt an AOS-CX REST login. Returns (ip, hostname-from-switch)
        on success, None otherwise. Errors are swallowed — a failed
        probe just means "not Aruba (or unreachable on REST)".
        """
        try:
            with driver_for(ip, self._api_user, self._api_pass) as drv:
                if drv.logged_in:
                    name = drv.get_hostname() or ip
                    return ip, name
        except Exception as exc:  # pragma: no cover
            log.debug("Scanner: REST probe failed for %s: %s", ip, exc)
        return None

    def _verify_via_rest(self, candidate_ips: List[str]) -> Dict[str, str]:
        """
        Probe candidate IPs concurrently. Returns {ip: hostname} for
        every host that authenticated to AOS-CX. Concurrency is bounded
        by self.api_workers (default 16) so a /24 with a thousand
        candidates still completes in a reasonable time.
        """
        if not candidate_ips:
            return {}

        log.info(
            "Scanner: probing %d non-keyword responders via AOS-CX REST",
            len(candidate_ips),
        )
        confirmed: Dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=self.api_workers,
                                thread_name_prefix="scan-probe") as ex:
            futures = [ex.submit(self._probe_one, ip) for ip in candidate_ips]
            for fut in as_completed(futures):
                result = fut.result()
                if result is not None:
                    ip, name = result
                    confirmed[ip] = name
        log.info(
            "Scanner: REST probe confirmed %d additional Aruba switch(es)",
            len(confirmed),
        )
        return confirmed

    def _write_ip_list(self, devices: Dict[str, str]) -> List[str]:
        # Fast path — DNS hostname matches one of the configured keywords
        keyword_hits: Dict[str, str] = {
            ip: name for ip, name in devices.items()
            if any(kw in name for kw in self.filter_keywords)
        }

        # Slow path — REST probe everything that pinged but didn't match
        rest_hits: Dict[str, str] = {}
        if self.verify_via_api:
            candidates = [ip for ip in devices if ip not in keyword_hits]
            rest_hits = self._verify_via_rest(candidates)
            # Backfill the device CSV with the real hostname from the switch,
            # so the next scan's diff doesn't keep flagging it as "new".
            for ip, hostname in rest_hits.items():
                devices[ip] = hostname

        all_ips = sorted(
            list(keyword_hits.keys()) + list(rest_hits.keys()),
            key=lambda ip: ipaddress.ip_address(ip),
        )

        # ── coverage safeguard ────────────────────────────────────────────
        prev_count = 0
        if os.path.exists(self.ip_list_output):
            try:
                with open(self.ip_list_output) as f:
                    prev_count = sum(1 for ln in f if ln.strip())
            except OSError:
                prev_count = 0

        new_count = len(all_ips)
        if (self.coverage_drop_pct > 0 and prev_count >= 10
                and new_count < prev_count * (1 - self.coverage_drop_pct / 100)):
            drop = round((prev_count - new_count) / prev_count * 100)
            summary = (f"Discovery coverage dropped sharply: this scan found "
                       f"{new_count} switch(es) vs {prev_count} previously "
                       f"(-{drop}%).")
            if self.coverage_guard:
                log.error("Scanner: %s Keeping previous ip_list; NOT overwriting.",
                          summary)
                self.notifier.send(
                    "[Aruba] Discovery coverage drop — list preserved",
                    summary + f"\n\nThe previous {prev_count}-switch list at "
                    f"{self.ip_list_output} was preserved, so monitoring and "
                    "backups are unchanged. Investigate discovery (routing, DNS, "
                    "credentials) before the next scan.")
                try:
                    with open(self.ip_list_output) as f:
                        return [ln.strip() for ln in f if ln.strip()]
                except OSError:
                    return all_ips
            else:
                log.error("Scanner: %s Overwriting anyway (coverage_guard off).",
                          summary)
                self.notifier.send("[Aruba] Discovery coverage drop", summary)

        os.makedirs(os.path.dirname(self.ip_list_output) or ".", exist_ok=True)
        with open(self.ip_list_output, "w") as f:
            f.writelines(ip + "\n" for ip in all_ips)

        log.info(
            "Scanner: wrote %d Aruba IPs to %s (%d via DNS keyword, %d via REST probe)",
            len(all_ips), self.ip_list_output, len(keyword_hits), len(rest_hits),
        )
        return all_ips

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
