"""
Subnet utilization health check (wireless distros).

Purpose
-------
The wireless VLANs get their addresses via DHCP relayed by IP helpers on the
two wireless distribution switches. When a helper (or DHCP) breaks, clients
stop getting leases and the subnet quietly empties out; when a pool is too
small for demand it fills up. Neither shows up in normal up/down monitoring.

This job SSHes to each distro once a night, reads the ARP table, counts how
many distinct host IPs are active in each configured /24, and emails when a
subnet's utilization crosses a low or high watermark:

  * below `low_pct`  -> likely an IP-helper / DHCP problem (few/no active hosts)
  * above `high_pct` -> pool nearly exhausted

Design notes
------------
* **Completely self-contained.** It does not touch the poller, backup,
  scanner or ARP-discovery paths, shares no state, and is only scheduled when
  ``[subnet_health] enabled = true``. If it's off (the default) this module is
  never even imported.
* **SSH only**, via netmiko (lazy import; ships with napalm). No REST, so it
  works against CX or ArubaOS-S distros regardless of REST availability.
* **Fail safe.** If it can't read ARP from the distros (both unreachable, or
  zero IPs parsed), it does NOT report every subnet as "low" -- it sends a
  distinct "couldn't collect" notice instead, so a collection failure can't
  masquerade as a fleet-wide outage.
"""

from __future__ import annotations

import configparser
import ipaddress
import logging
import os
import re
from typing import Dict, List, Optional, Set, Tuple

from aruba_agent.notifier      import EmailNotifier
from aruba_agent.secrets_store import decrypt as _decrypt

log = logging.getLogger(__name__)

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class SubnetHealthTask:
    """Nightly ARP-based subnet utilization monitor for the wireless distros."""

    def __init__(self, cfg: configparser.ConfigParser, notifier: EmailNotifier) -> None:
        sh = cfg["subnet_health"] if "subnet_health" in cfg else {}
        cr = cfg["credentials"]   if "credentials"   in cfg else {}

        self.notifier = notifier

        # Distros to poll (comma / space separated).
        self.distros: List[str] = [
            d.strip() for d in re.split(r"[,\s]+", sh.get("distros", "")) if d.strip()
        ]

        # netmiko device_type for the distros. Wireless distros here are
        # Aruba CX, so aruba_aoscx (SSH) is the default; override for
        # ProCurve (hp_procurve) or Cisco (cisco_ios).
        self.device_type = (sh.get("device_type", "aruba_aoscx") or "aruba_aoscx").strip()
        self.arp_command = (sh.get("arp_command", "show arp") or "show arp").strip()

        # Credentials: reuse the default monitoring account unless the
        # section overrides it.
        self.username = (sh.get("username", "") or cr.get("username", "admin")).strip()
        self.password = _decrypt(sh.get("password", "")) or _decrypt(cr.get("password", ""))
        self.enable_secret = _decrypt(sh.get("enable_secret", ""))

        # Thresholds + sizing.
        self.low_pct  = _num(sh.get("low_pct",  "10"), 10.0)
        self.high_pct = _num(sh.get("high_pct", "90"), 90.0)
        self.usable   = int(_num(sh.get("usable_per_subnet", "254"), 254))
        self.timeout  = int(_num(sh.get("timeout", "30"), 30))

        # Subnets: a file of "label CIDR" lines (preferred) and/or an
        # inline list. Missing / unreadable file is tolerated.
        self.subnets_file = (sh.get("subnets_file", "") or "").strip()
        self._inline      = sh.get("subnets", "") or ""

    # -- subnet list ----------------------------------------------------------

    def _load_subnets(self) -> List[Tuple[str, "ipaddress.IPv4Network"]]:
        """Return [(label, network), ...] from the file and/or inline list.
        Lines look like 'vlan500 172.18.0.0/24' or just '172.18.0.0/24'."""
        raw: List[str] = []
        if self.subnets_file and os.path.exists(self.subnets_file):
            try:
                with open(self.subnets_file) as f:
                    raw.extend(f.read().splitlines())
            except OSError as exc:
                log.warning("subnet_health: cannot read %s: %s", self.subnets_file, exc)
        raw.extend(re.split(r"[\n,]+", self._inline))

        out: List[Tuple[str, ipaddress.IPv4Network]] = []
        seen: Set[str] = set()
        for line in raw:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                label, cidr = parts[0], parts[1]
            else:
                label, cidr = "", parts[0]
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                log.warning("subnet_health: bad subnet %r -- skipping", cidr)
                continue
            if not isinstance(net, ipaddress.IPv4Network) or str(net) in seen:
                continue
            seen.add(str(net))
            out.append((label or str(net), net))
        return out

    # -- ARP collection over SSH ----------------------------------------------

    def _collect_active_ips(self) -> Tuple[Set[str], List[str]]:
        """SSH each distro, run the ARP command, return (set of IPv4 strings
        seen, list of per-distro error strings)."""
        ips: Set[str] = set()
        errors: List[str] = []
        try:
            from netmiko import ConnectHandler          # lazy
        except ImportError as exc:
            errors.append(f"netmiko not installed ({exc})")
            return ips, errors

        for host in self.distros:
            params = {
                "device_type": self.device_type,
                "host":        host,
                "username":    self.username,
                "password":    self.password,
                "timeout":     self.timeout,
                "fast_cli":    False,
            }
            if self.enable_secret:
                params["secret"] = self.enable_secret
            net = None
            try:
                net = ConnectHandler(**params)
                if self.enable_secret:
                    try:
                        net.enable()
                    except Exception:
                        pass
                try:
                    net.clear_buffer()
                except Exception:
                    pass
                try:
                    out = net.send_command(self.arp_command, read_timeout=120)
                except TypeError:
                    out = net.send_command(self.arp_command)
                found = _IPV4.findall(out or "")
                for ip in found:
                    ips.add(ip)
                log.info("subnet_health: %s -> %d ARP IPs", host, len(found))
            except Exception as exc:
                msg = f"{host}: {type(exc).__name__}: {exc}"
                errors.append(msg)
                log.warning("subnet_health: %s", msg)
            finally:
                if net is not None:
                    try:
                        net.disconnect()
                    except Exception:
                        pass
        return ips, errors

    # -- evaluation -----------------------------------------------------------

    def evaluate(self, active_ips: Set[str],
                 subnets: List[Tuple[str, "ipaddress.IPv4Network"]]) -> Dict[str, list]:
        """Bucket active IPs into subnets and flag low/high utilization.
        Pure function (no I/O) so it's easy to unit-test."""
        parsed: List[ipaddress.IPv4Address] = []
        for s in active_ips:
            try:
                parsed.append(ipaddress.ip_address(s))
            except ValueError:
                continue

        low: list = []
        high: list = []
        for label, net in subnets:
            count = sum(1 for ip in parsed if ip in net)
            pct   = (count / self.usable * 100.0) if self.usable else 0.0
            row   = {"label": label, "cidr": str(net), "count": count,
                     "usable": self.usable, "pct": round(pct, 1)}
            if pct < self.low_pct:
                low.append(row)
            elif pct > self.high_pct:
                high.append(row)
        return {"low": low, "high": high}

    # -- run ------------------------------------------------------------------

    def run(self) -> None:
        subnets = self._load_subnets()
        if not self.distros or not subnets:
            log.warning("subnet_health: nothing to do (distros=%d subnets=%d) -- "
                        "check [subnet_health] distros / subnets_file",
                        len(self.distros), len(subnets))
            return

        active, errors = self._collect_active_ips()

        # Fail-safe: if we couldn't read ARP at all, don't claim every subnet
        # is empty -- report the collection failure and stop.
        if not active:
            body = ("Subnet health check could not read ARP from the wireless "
                    "distros, so utilization was NOT evaluated.\n\n"
                    "Distros: " + ", ".join(self.distros) + "\n\n"
                    "Errors:\n  " + ("\n  ".join(errors) if errors else "(no IPs parsed)"))
            log.error("subnet_health: no ARP data collected; %s", errors)
            self.notifier.send("[Network Agent] Subnet health check FAILED to collect ARP", body)
            return

        result = self.evaluate(active, subnets)
        low, high = result["low"], result["high"]
        log.info("subnet_health: evaluated %d subnets, %d low, %d high (%d active IPs)",
                 len(subnets), len(low), len(high), len(active))

        if not low and not high:
            return   # all subnets healthy -- stay quiet

        lines: List[str] = []
        if low:
            lines.append(f"LOW utilization (< {self.low_pct:g}%) -- possible IP-helper / DHCP problem:")
            lines += [f"  {r['label']:<16} {r['cidr']:<18} {r['count']:>3}/{r['usable']} "
                      f"({r['pct']}%)" for r in sorted(low, key=lambda r: r['pct'])]
            lines.append("")
        if high:
            lines.append(f"HIGH utilization (> {self.high_pct:g}%) -- pool nearly exhausted:")
            lines += [f"  {r['label']:<16} {r['cidr']:<18} {r['count']:>3}/{r['usable']} "
                      f"({r['pct']}%)" for r in sorted(high, key=lambda r: -r['pct'])]
            lines.append("")
        if errors:
            lines.append("Note: one or more distros returned an error this run:")
            lines += [f"  {e}" for e in errors]
            lines.append("")
        lines.append(f"Distros polled: {', '.join(self.distros)}")
        lines.append("Utilization is based on distinct host IPs seen in the distro ARP tables.")

        subject = f"[Network Agent] Subnet utilization alert -- {len(low)} low, {len(high)} high"
        self.notifier.send(subject, "\n".join(lines))


def _num(val: str, default: float) -> float:
    try:
        return float(str(val).strip())
    except (TypeError, ValueError):
        return default
