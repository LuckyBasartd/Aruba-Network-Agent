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
import threading
from datetime import datetime, timedelta
from typing import Dict, List

from aruba_agent.drivers          import driver_for
from aruba_agent.drivers.detector import VendorDetector
from aruba_agent.notifier         import EmailNotifier
from aruba_agent.snmp             import SnmpAgent
from aruba_agent.state            import AgentState

from typing import Optional

log = logging.getLogger(__name__)


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
    ) -> None:
        self.name              = name
        self.host              = host
        self.notifier          = notifier
        self.state             = state
        self.poll_interval     = poll_interval
        self.failure_threshold = failure_threshold
        self._username         = username
        self._password         = password
        self._verify           = verify_ssl
        self._stop             = threading.Event()
        self._snmp             = snmp       # None => use driver-based REST poll
        self._detector         = detector   # None => skip vendor detection

        state.register_switch(name, host)
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

    def _poll(self) -> None:
        ok = self._poll_snmp() if self._snmp is not None else self._poll_rest()

        sw = self.state.switches.get(self.name)
        if sw is None:
            return

        if ok:
            self.state.update_switch(
                self.name,
                last_seen  = datetime.now(),
                failures   = 0,
                last_event = f"Reachable at {datetime.now().strftime('%H:%M:%S')}",
            )
            if sw.is_down:
                self.state.update_switch(self.name, is_down=False)
                log.info("Switch RESTORED: %s (%s)", self.name, self.host)
                self.notifier.send(
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
                self.notifier.send(
                    f"[Aruba] Switch DOWN: {self.name}",
                    (
                        f"Switch Management Reachability — DOWN\n"
                        f"Switch   : {self.name}\n"
                        f"Host     : {self.host}\n"
                        f"Failures : {new_failures} consecutive\n"
                        f"Interval : {self.poll_interval}s\n"
                    ),
                )

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
    ) -> None:
        """Start monitoring *host* if not already tracked."""
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
            )
            m.start()
            self._monitors[host] = m
            log.info("Monitor added: %s (%s)", name, host)

    def sync(self, ip_list: List[str]) -> None:
        """
        Called by the scanner after each run.
        Adds a monitor for any IP not already being watched.
        Uses the IP as the display name until the first successful poll
        resolves the real hostname.
        """
        for ip in ip_list:
            self.add(host=ip, name=ip)

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
    manager = SwitchMonitorManager(
        username          = cfg.get("credentials", "username", fallback="admin"),
        password          = cfg.get("credentials", "password", fallback=""),
        notifier          = notifier,
        state             = state,
        verify_ssl        = False,
        poll_interval     = 30,
        failure_threshold = 3,
        snmp              = snmp,
        detector          = detector,
    )

    # Seed with any manually configured switches
    for sec in cfg.sections():
        if not sec.startswith("switch."):
            continue
        name = sec[len("switch."):]
        sw   = cfg[sec]
        manager.add(
            host              = sw["host"],
            name              = name,
            username          = sw.get("username", ""),
            password          = sw.get("password", ""),
            verify_ssl        = sw.getboolean("verify_ssl", False),
            poll_interval     = sw.getint("poll_interval", 30),
            failure_threshold = sw.getint("failure_threshold", 3),
        )

    return manager
