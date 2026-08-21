"""
Switch reachability poller — "Dead Man's Switch" for AOS-CX management plane.

Polls each switch's /system endpoint every N seconds.
Fires email alerts (and updates AgentState) on:
  - 3+ consecutive failures  → DOWN alert
  - Recovery after DOWN       → RESTORED alert

SwitchMonitorManager handles dynamic registration — the scanner calls
manager.sync(ip_list) after every scan so newly discovered switches are
automatically added to monitoring without a service restart.
"""

from __future__ import annotations

import configparser
import logging
import random
import re
import socket
import threading
from datetime import datetime, timedelta
from typing import Dict, List

from aruba_agent.drivers          import driver_for
from aruba_agent.drivers.detector import VendorDetector
from aruba_agent.notifier         import EmailNotifier
from aruba_agent.secrets_store    import decrypt as _decrypt
from aruba_agent.snmp             import SnmpAgent
from aruba_agent.state            import AgentState

from typing import Optional


log = logging.getLogger(__name__)

# Pull a version token out of an SNMP sysDescr string. Works across the
# vendors we monitor:
#   Cisco IOS   "... Version 12.2(55)SE9, RELEASE SOFTWARE (fc1) ..."
#   Cisco IOSXE "... Version 17.3.3, RELEASE SOFTWARE (fc7) ..."
#   Arista EOS  "Arista Networks EOS version 4.30.1F running on ..."
#   ArubaOS-CX  "ArubaOS-CX ... version 10.13.1000 ..."
# We grab the first token after "version" and trim trailing punctuation.
# Cisco / Arista / IOS style: "... Version 15.2(7)E, ..."
_VERSION_KEYWORD_RE = re.compile(r"version\s+([^\s,;]+)", re.IGNORECASE)
# Aruba AOS-CX style sysDescr has no "version" keyword; the build lives in a
# trailing token like "FL.10.13.1150" / "PL.10.13.1150".
_VERSION_TOKEN_RE = re.compile(r"\b([A-Z]{2}\.\d+(?:\.\d+)+)\b")


def _parse_version_from_descr(descr: Optional[str]) -> str:
    """Best-effort version extraction from sysDescr. '' when nothing matches."""
    if not descr:
        return ""
    m = _VERSION_KEYWORD_RE.search(descr)
    if m:
        return m.group(1).strip().rstrip(".,;")
    m = _VERSION_TOKEN_RE.search(descr)
    if m:
        return m.group(1)
    return ""


class SwitchMonitor:
    def __init__(
        self,
        name: str,
        host: str,
        username: str,
        password: str,
        notifier: EmailNotifier,
        state: AgentState,
        verify_ssl: bool       = False,
        poll_interval: int     = 30,
        failure_threshold: int = 3,
        snmp:     Optional[SnmpAgent]      = None,
        detector: Optional[VendorDetector] = None,
        alert_dedup_seconds: int = 300,
        monitor_mode: str      = "auto",
    ) -> None:
        self.name              = name
        self.host              = host
        self.notifier          = notifier
        self.state             = state
        self.poll_interval     = poll_interval
        self.failure_threshold = failure_threshold
        self.monitor_mode      = monitor_mode or "auto"
        self._username         = username
        self._password         = password
        self._verify           = verify_ssl
        self._stop             = threading.Event()
        self._snmp             = snmp       # None => use driver-based REST poll
        self._detector         = detector   # None => skip vendor detection

        # v3.0.2 (T2.1): Alert deduplication.
        # Per-kind timestamp of the most recent alert we actually sent.
        # When a new alert of the same kind would fire within
        # ``alert_dedup_seconds``, we suppress + log instead — keeps
        # email volume bounded when a switch flaps repeatedly.
        # 0 (or any non-positive) disables suppression entirely.
        self._alert_dedup_seconds = max(0, int(alert_dedup_seconds))
        self._last_alert: Dict[str, datetime] = {}

        state.register_switch(name, host, monitor_mode=self.monitor_mode)
        # Per-switch backoff timer for "no profile worked" — keeps
        # an unclassified switch from running detection (and pinging
        # every profile) every poll cycle.
        self._classification_cooldown_until: Optional[datetime] = None

    # ─── reachability paths ─────────────────────────────────────────────────

    # If the detector tries every profile and none authenticates, wait
    # this long before retrying. Otherwise an Aruba-only profile against
    # a Cisco-only switch (or any never-classifiable host) would re-run
    # discovery every 30 seconds, burning SNMP calls on every profile.
    _CLASSIFICATION_COOLDOWN_SECONDS = 300

    def _poll_snmp(self) -> bool:
        """
        Single SNMPv3 GET on sysUpTime.0 against the host's pinned
        SNMP profile. No session, no logout, no leak.

        Profile resolution
        ------------------
        * If the host already has a pinned profile in SwitchState
          (from a previous successful detection — possibly across
          a restart), use it directly.
        * Otherwise, the C6.2 detector iterates the profile registry
          and pins the winner. If none authenticate, we set a
          cooldown so we don't keep re-trying every poll.
        * sysName resolution piggy-backs on the same profile.
        """
        sw = self.state.switches.get(self.name)
        if sw is None:
            return False

        profile_name = sw.snmp_profile

        # ── New host (or pre-C6.2 state restore): run discovery ────────────
        if not profile_name:
            # Cooldown — skip discovery if we recently failed
            if (self._classification_cooldown_until is not None and
                    datetime.now() < self._classification_cooldown_until):
                return False

            if self._detector is not None:
                result = self._detector.detect_with_profile(self.host)
                if result is not None:
                    vendor, profile_name = result
                    self.state.update_switch(
                        self.name, vendor=vendor, snmp_profile=profile_name,
                    )
                    # Drop any prior cooldown — the host is classified
                    self._classification_cooldown_until = None
                else:
                    # No profile worked. Back off so we don't hammer
                    # the registry on every poll.
                    self._classification_cooldown_until = (
                        datetime.now() +
                        timedelta(seconds=self._CLASSIFICATION_COOLDOWN_SECONDS)
                    )
                    log.warning(
                        "Switch %s: no SNMP profile authenticated — "
                        "will retry in %d seconds",
                        self.host, self._CLASSIFICATION_COOLDOWN_SECONDS,
                    )
                    return False
            else:
                # No detector available — fall back to default profile
                # (which is what an empty profile_name resolves to in
                # SnmpAgent.get).
                profile_name = None

        # ── Pinned profile path: poll using the host's known profile ──────
        ok = self._snmp.is_reachable(self.host, profile_name=profile_name)
        if ok:
            if not sw.hostname or sw.hostname == self.name:
                hostname = self._snmp.get_sys_name(
                    self.host, profile_name=profile_name,
                )
                if hostname and hostname != self.name:
                    self.state.update_switch(self.name, hostname=hostname)
        return ok

    def _poll_rest(self) -> bool:
        """
        Legacy REST-based reachability — opens a vendor driver session,
        calls is_reachable + get_hostname, closes the session. Kept as
        the fallback path for installs that haven't moved to SNMPv3 yet.
        """
        try:
            with driver_for(self.host, self._username, self._password,
                            verify_ssl=self._verify) as drv:
                ok = drv.logged_in and drv.is_reachable()
                if ok and drv.logged_in:
                    hostname = drv.get_hostname()
                    if hostname and hostname != self.name:
                        self.state.update_switch(self.name, hostname=hostname)
                return ok
        except Exception:
            return False

    def _poll_icmp(self) -> bool:
        """
        ICMP-only reachability for hosts that don't grant SNMP or
        management-plane access (per-host monitor_mode = "icmp").

        Uses subprocess to invoke /usr/bin/ping with -c1 -W2 so we
        don't have to drag Scapy / raw sockets into the hot poll path.
        The systemd unit already grants CAP_NET_RAW for the scanner;
        unprivileged ping works for non-root users with /bin/ping
        suid'd on every RHEL family distro.
        """
        import subprocess
        try:
            r = subprocess.run(
                ["ping", "-n", "-c", "1", "-W", "2", self.host],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            return r.returncode == 0
        except (FileNotFoundError, subprocess.SubprocessError):
            # If ping isn't available we treat the host as unreachable.
            # Don't crash the monitor thread for this.
            return False

    def _ssh_reachable(self, port: int = 22, timeout: float = 3.0) -> bool:
        """Lightweight SSH liveness check: open a TCP connection to the
        SSH port and confirm the server sends an ``SSH-`` identification
        banner. Confirms the management plane is up without a full login
        (a full auth every poll would be slow and risks lockouts)."""
        try:
            with socket.create_connection((self.host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                banner = sock.recv(64)
            return banner.startswith(b"SSH-")
        except OSError:
            return False

    def _poll_reachability(self):
        """SNMP-first reachability with ICMP + SSH fallback, for the
        SNMP-polled modes (auto / snmp_ro / snmp_rw). Returns
        ``(ok, snmp_ok)``.

        Ladder (operator spec):
          * SNMP ok                          -> UP  (snmp healthy)
          * SNMP fail, ICMP fail             -> DOWN
          * SNMP fail, ICMP ok, SSH fail     -> DOWN
          * SNMP fail, ICMP ok, SSH ok       -> UP  (SNMP degraded)

        This stops a switch whose SNMP is merely misconfigured — but is
        pingable and SSH-reachable — from being flagged DOWN.
        """
        if self._poll_snmp():
            return True, True
        # SNMP failed. Is the box reachable at all?
        if not self._poll_icmp():
            return False, True
        # Pings but SNMP is dead — confirm the management plane via SSH.
        if self._ssh_reachable():
            return True, False          # UP, but SNMP not answering
        return False, True              # ICMP-only, no manageable plane -> DOWN

    def _poll(self) -> None:
        # v3.0.3: dispatch based on per-host monitor_mode.
        # The mode lives in AgentState — manual_hosts.py and the
        # scanner both populate it via register_switch().
        sw_now = self.state.switches.get(self.name)
        mode   = (sw_now.monitor_mode if sw_now else "auto") or "auto"

        snmp_ok = True   # only meaningful for SNMP-polled modes
        if mode == "icmp":
            ok = self._poll_icmp()
        elif self._snmp is not None and mode in ("snmp_ro", "snmp_rw", "auto"):
            ok, snmp_ok = self._poll_reachability()
        else:
            ok = self._poll_rest()

        sw = self.state.switches.get(self.name)
        if sw is None:
            return

        if ok:
            ts = datetime.now().strftime('%H:%M:%S')
            event = (f"Reachable at {ts}" if snmp_ok
                     else f"Reachable via SSH — SNMP not responding at {ts}")
            self.state.update_switch(
                self.name,
                last_seen  = datetime.now(),
                failures   = 0,
                last_event = event,
            )
            # Flag / clear the "SNMP misconfigured" warning (persists on flip).
            if self.state.set_snmp_health(self.name, snmp_ok):
                if snmp_ok:
                    log.info("Switch %s (%s): SNMP polling restored",
                             self.name, self.host)
                else:
                    log.warning("Switch %s (%s): reachable via SSH but SNMP not "
                                "responding — check SNMP config", self.name, self.host)
            # Resolve firmware/OS version once, lazily, on a healthy poll.
            self._maybe_resolve_os_version(sw)
            if sw.is_down:
                self.state.update_switch(self.name, is_down=False)
                log.info("Switch RESTORED: %s (%s)", self.name, self.host)
                self._maybe_send_alert(
                    "restored",
                    f"[Aruba] Switch RESTORED: {self.name}",
                    (
                        f"Switch Management Reachability — RESTORED\n"
                        f"Switch : {self.name}\n"
                        f"Host   : {self.host}\n"
                        f"Status : Management plane reachable (HTTP 200)\n"
                    ),
                )
        else:
            new_failures = sw.failures + 1
            self.state.update_switch(
                self.name,
                failures   = new_failures,
                last_event = f"Poll failed ({new_failures}x) at {datetime.now().strftime('%H:%M:%S')}",
            )
            log.warning(
                "Switch poll failure %d/%d: %s (%s)",
                new_failures, self.failure_threshold, self.name, self.host,
            )
            if new_failures >= self.failure_threshold and not sw.is_down:
                self.state.update_switch(self.name, is_down=True)
                log.error("Switch DOWN: %s (%s)", self.name, self.host)
                self._maybe_send_alert(
                    "down",
                    f"[Aruba] Switch DOWN: {self.name}",
                    (
                        f"Switch Management Reachability — DOWN\n"
                        f"Switch   : {self.name}\n"
                        f"Host     : {self.host}\n"
                        f"Failures : {new_failures} consecutive\n"
                        f"Interval : {self.poll_interval}s\n"
                    ),
                )

    def _maybe_resolve_os_version(self, sw) -> None:
        """
        Populate SwitchState.os_version the first time we can, then
        never poll for it again (a switch's version only changes on a
        firmware upgrade, which restarts the box and re-runs this).

        Source per the operator's spec:
          * Aruba  -> firmware via the AOS-CX REST API (driver get_facts),
                      but only when the host's mode grants driver access.
          * Cisco / Arista / everything else, or Aruba when the driver
                      path is unavailable -> parse SNMP sysDescr.
        """
        if sw is None or sw.os_version:
            return

        vendor = sw.vendor or ""
        mode   = sw.monitor_mode or "auto"
        version = ""

        # Aruba: prefer the API firmware string. The REST session uses its
        # own credentials (independent of SNMP RO/RW), so try it for any
        # Aruba host that has a management plane. Only pure-ICMP hosts, which
        # by definition expose no management API, are skipped. On login
        # failure the driver returns "" and we fall through to sysDescr.
        if vendor.startswith("aruba") and mode != "icmp":
            version = self._os_version_via_driver(vendor)

        # SNMP sysDescr fallback (and the primary path for Cisco/Arista).
        if not version and self._snmp is not None:
            try:
                descr = self._snmp.get_sys_descr(
                    self.host, profile_name=sw.snmp_profile or None,
                )
            except Exception as exc:
                log.debug("sysDescr fetch failed for %s: %s", self.host, exc)
                descr = None
            version = _parse_version_from_descr(descr)

        if version:
            self.state.set_os_version(self.name, version)
            log.info("Resolved OS version for %s (%s): %s",
                     self.name, self.host, version)

    def _os_version_via_driver(self, vendor_hint: str) -> str:
        """Open a vendor driver session and read the running firmware
        version. Returns '' on any failure — the caller falls back to
        SNMP sysDescr.

        Aruba AOS-CX: the version lives at the REST ``/firmware``
        endpoint (``current_version``), NOT ``/system`` — on 10.13 the
        latter doesn't expose ``software_version`` at all. We reach it
        through the session's get_firmware_status() helper. Other
        vendors fall through to the generic get_facts().os_version.
        """
        try:
            with driver_for(self.host, self._username, self._password,
                            verify_ssl=self._verify,
                            vendor_hint=vendor_hint or None) as drv:
                if not getattr(drv, "logged_in", False):
                    return ""

                # Aruba: prefer the firmware endpoint.
                session = getattr(drv, "session", None)
                if session is not None and hasattr(session, "get_firmware_status"):
                    try:
                        fw = session.get_firmware_status()
                    except Exception as exc:
                        log.debug("Firmware endpoint failed for %s: %s",
                                  self.host, exc)
                        fw = None
                    if fw:
                        ver = (fw.get("current_version")
                               or fw.get("primary_version") or "")
                        if ver:
                            return ver

                # Generic fallback (Cisco / Arista, or Aruba w/o firmware ep).
                facts = drv.get_facts()
                return (facts.os_version if facts else "") or ""
        except Exception as exc:
            log.debug("Driver facts failed for %s: %s", self.host, exc)
            return ""

    def _maybe_send_alert(self, kind: str, subject: str, body: str) -> None:
        """
        Send a reachability alert, unless we already sent one of the
        same kind ('down' or 'restored') within the dedup window.

        Why kind-specific instead of any-kind: an operator who got a
        DOWN email still wants to see the RESTORED follow-up so they
        know things stabilised. We only suppress *repeats* of the
        same state change — that's what kills the email storm during
        a flapping incident.

        Updates the kind's timestamp on send AND on suppress, so a
        burst of 20 transitions in 30 seconds still only emits ~2
        emails per dedup window, not 1+ per minute.
        """
        if self._alert_dedup_seconds > 0:
            last = self._last_alert.get(kind)
            now  = datetime.now()
            if last is not None:
                elapsed = (now - last).total_seconds()
                if elapsed < self._alert_dedup_seconds:
                    log.info(
                        "Alert SUPPRESSED (%s): %s — last sent %.0fs ago, "
                        "dedup window %ds",
                        kind, self.name, elapsed, self._alert_dedup_seconds,
                    )
                    # Refresh the timestamp so the window stays warm
                    # while the host keeps flapping. Without this a
                    # switch that flaps every 4 minutes would dodge a
                    # 5-min window and email every cycle.
                    self._last_alert[kind] = now
                    return
            self._last_alert[kind] = now

        self.notifier.send(subject, body)

    def start(self) -> None:
        def _run() -> None:
            log.debug("Switch monitor started: %s (%s)", self.name, self.host)

            # Stagger the first poll over the full cycle window so the
            # entire fleet doesn't hammer pysnmp + the GIL in lockstep.
            # Without this, 200 SwitchMonitor threads spawned within
            # milliseconds of each other all wake every 30s at the
            # same instant — the waitress thread pool gets starved
            # and the dashboard stops responding.
            initial_delay = random.uniform(0, self.poll_interval)
            if self._stop.wait(initial_delay):
                return                              # stopped during initial delay

            while not self._stop.is_set():
                self._poll()
                self._stop.wait(self.poll_interval)
            log.debug("Switch monitor stopped: %s", self.name)

        threading.Thread(target=_run, name=f"sw-{self.name}", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()


class SwitchMonitorManager:
    """
    Manages a dynamic pool of SwitchMonitor instances.

    The scanner calls sync(ip_list) after each discovery run.
    New IPs get a monitor spun up automatically; existing ones are left alone.
    Manual [switch.*] entries in config.ini are pre-seeded at startup.
    """

    def __init__(
        self,
        username: str,
        password: str,
        notifier: EmailNotifier,
        state: AgentState,
        verify_ssl: bool       = False,
        poll_interval: int     = 30,
        failure_threshold: int = 3,
        snmp:     Optional[SnmpAgent]      = None,
        detector: Optional[VendorDetector] = None,
        alert_dedup_seconds: int = 300,
    ) -> None:
        self._username         = username
        self._password         = password
        self._notifier         = notifier
        self._state            = state
        self._verify           = verify_ssl
        self._poll_interval    = poll_interval
        self._failure_threshold = failure_threshold
        self._snmp             = snmp
        self._detector         = detector
        self._alert_dedup_seconds = alert_dedup_seconds
        self._monitors: Dict[str, SwitchMonitor] = {}   # keyed by host IP
        self._lock = threading.Lock()

    def add(
        self,
        host: str,
        name: str,
        username: str  = "",
        password: str  = "",
        verify_ssl: bool       = False,
        poll_interval: int     = 0,
        failure_threshold: int = 0,
        monitor_mode: str      = "auto",
    ) -> None:
        """Start monitoring *host* if not already tracked.
        ``monitor_mode`` flows through to SwitchMonitor + AgentState so
        ping-only / SNMP-read-only manual hosts skip the heavier
        management-plane probes."""
        with self._lock:
            if host in self._monitors:
                return
            m = SwitchMonitor(
                name              = name,
                host              = host,
                username          = username or self._username,
                password          = password or self._password,
                notifier          = self._notifier,
                state             = self._state,
                verify_ssl        = verify_ssl or self._verify,
                poll_interval     = poll_interval or self._poll_interval,
                failure_threshold = failure_threshold or self._failure_threshold,
                snmp              = self._snmp,
                detector          = self._detector,
                alert_dedup_seconds = self._alert_dedup_seconds,
                monitor_mode      = monitor_mode or "auto",
            )
            m.start()
            self._monitors[host] = m
            log.info("Monitor added: %s (%s) mode=%s", name, host,
                     monitor_mode or "auto")

    def sync(self, ip_list: List[str]) -> None:
        """
        Called by the scanner after each run.
        Adds a monitor for any IP not already being watched.
        Uses the IP as the display name until the first successful poll
        resolves the real hostname.
        """
        for ip in ip_list:
            self.add(host=ip, name=ip)

    def remove(self, host: str) -> bool:
        """
        Stop monitoring ``host`` and drop the SwitchMonitor. Returns
        True when a monitor was actually removed.

        Used by the Settings → Manual Hosts page so removing a host
        from the registry stops polling it immediately rather than
        waiting for the next agent restart.
        """
        with self._lock:
            m = self._monitors.pop(host, None)
        if m is None:
            return False
        try:
            m.stop()
        except Exception as exc:
            log.warning("Monitor stop failed for %s: %s", host, exc)
        log.info("Monitor removed: %s", host)
        return True

    def stop_all(self) -> None:
        with self._lock:
            for m in self._monitors.values():
                m.stop()


def start_all(
    cfg: configparser.ConfigParser,
    notifier: EmailNotifier,
    state: AgentState,
    snmp:     Optional[SnmpAgent]      = None,
    detector: Optional[VendorDetector] = None,
) -> SwitchMonitorManager:
    """
    Create a SwitchMonitorManager seeded from [credentials] defaults,
    then add any static [switch.*] entries from config.ini.
    Returns the manager so the scanner can call manager.sync() later.

    When `snmp` is provided every monitor uses SNMPv3 for the 30s
    reachability poll instead of opening a vendor REST session — no
    session state on the switch, no AOS-CX session-limit risk, and
    the same code path works for Cisco / Arista / Aruba alike.
    """
    if snmp is not None:
        log.info("Switch poller: SNMPv3 reachability ENABLED — "
                 "REST sessions used only for hostname / config tasks")
    else:
        log.info("Switch poller: SNMPv3 not configured — "
                 "falling back to REST-based reachability per poll")

    # Global defaults come from [credentials] only — per-switch overrides are applied
    # inside manager.add() via the individual [switch.*] sections below.
    # There is no global [monitoring] section; per-switch values default to the
    # constants defined in SwitchMonitor.__init__ (poll_interval=30, threshold=3).
    # Decrypt the global [credentials] password once on construction —
    # SwitchMonitorManager hands it to every per-host driver later, so
    # it expects cleartext (as it always has).
    # T2.1: alert dedup window. [agent] alert_dedup_minutes (default 5);
    # 0 disables. Stored as seconds since timedelta math is in seconds.
    try:
        dedup_minutes = int(cfg.get("agent", "alert_dedup_minutes", fallback="5"))
    except (ValueError, TypeError):
        dedup_minutes = 5
    dedup_seconds = max(0, dedup_minutes) * 60

    manager = SwitchMonitorManager(
        username          = cfg.get("credentials", "username", fallback="admin"),
        password          = _decrypt(
            cfg.get("credentials", "password", fallback="")
        ),
        notifier          = notifier,
        state             = state,
        verify_ssl        = False,
        poll_interval     = 30,
        failure_threshold = 3,
        snmp              = snmp,
        detector          = detector,
        alert_dedup_seconds = dedup_seconds,
    )
    log.info("Alert dedup window: %d minute(s) per host per alert kind",
             dedup_minutes)

    # Seed with any manually configured switches.
    # Per-switch passwords (rare but supported) may also be encrypted.
    for sec in cfg.sections():
        if not sec.startswith("switch."):
            continue
        name = sec[len("switch."):]
        sw   = cfg[sec]
        manager.add(
            host              = sw["host"],
            name              = name,
            username          = sw.get("username", ""),
            password          = _decrypt(sw.get("password", "")),
            verify_ssl        = sw.getboolean("verify_ssl", False),
            poll_interval     = sw.getint("poll_interval", 30),
            failure_threshold = sw.getint("failure_threshold", 3),
        )

    return manager
