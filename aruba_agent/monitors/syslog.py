"""
UDP Syslog listener — AP state change detection (AOS 8.10).

Handles two Aruba syslog formats from the Mobility Conductor / Director:

Format 1 — CEF (Common Event Format):
  CEF:0|Aruba|A92xx|...|deviceProcessName=stm ... msg=<400168> ... Added AP <MAC>-<AP-Name>
  CEF:0|Aruba|A92xx|...|deviceProcessName=stm ... msg=<400169> ... Deleted AP <MAC>-<AP-Name>

Format 2 — Plain BSD syslog:
  <133>Apr  8 14:12:33 2026 9240-MD-3 stm[13821]: <400168> ... Added AP <MAC>-<AP-Name>
  <133>Apr  8 14:12:33 2026 9240-MD-3 stm[13821]: <400169> ... Deleted AP <MAC>-<AP-Name>

AP name is extracted from the portion after the last MAC address dash separator.
Multi-radio APs send one message per radio (same AP name, different MACs).
A per-AP-name cooldown (60 s) prevents duplicate emails for the same event.
"""

from __future__ import annotations

import configparser
import logging
import re
import socketserver
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Tuple

from aruba_agent.notifier import EmailNotifier
from aruba_agent.state    import AgentState

log = logging.getLogger(__name__)

# ── Shared regex ──────────────────────────────────────────────────────────────
# Matches "Added AP" or "Deleted AP" followed by MAC-APName anywhere in the line
_AP_EVENT_RE = re.compile(
    r"(?P<action>Added|Deleted)\s+AP\s+"
    r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}-(?P<ap_name>\S+)",
    re.IGNORECASE,
)

# Matches stm message 305003: "AP <name> is down"
_AP_IS_DOWN_RE = re.compile(
    r"<305003>\s.*?\bAP\s+(?P<ap_name>\S+)\s+is\s+down",
    re.IGNORECASE,
)

# Matches stm message 305061: "AP <name> ip ... down, reason: ..."
# Also matches the simpler variant "AP <name> ... down"
_AP_HB_TIMEOUT_RE = re.compile(
    r"<305061>\s.*?\bAP\s+(?P<ap_name>\S+)\s+(?:ip\s+\S+\s+.*?)?down",
    re.IGNORECASE,
)

# ── Legacy plain-syslog nanny fallback ────────────────────────────────────────
_NANNY_RE = re.compile(
    r"nanny(?:\[\d+\])?:\s+(?P<ap_name>\S+)\s+is\s+now\s+(?P<state>up|down)",
    re.IGNORECASE,
)

# Cooldown in seconds — suppress duplicate events for the same AP within this window
_DEDUP_WINDOW = 60


def _parse(raw: str) -> tuple[str, str] | None:
    """
    Returns (ap_name, state) or None if not an AP event.
    state is 'up' or 'down'.
    Works for both CEF and plain BSD syslog formats.
    """
    # _AP_EVENT_RE works on both CEF and plain syslog since both contain
    # "Added AP MAC-Name" or "Deleted AP MAC-Name" in the message body
    m = _AP_EVENT_RE.search(raw)
    if m:
        action  = m.group("action").lower()
        ap_name = m.group("ap_name").strip()
        state   = "up" if action == "added" else "down"
        return ap_name, state

    # 305003: "AP <name> is down" — definitive down from stm
    m = _AP_IS_DOWN_RE.search(raw)
    if m:
        return m.group("ap_name").strip(), "down"

    # 305061: "AP <name> ip ... down, reason: ..." — controller heartbeat timeout
    m = _AP_HB_TIMEOUT_RE.search(raw)
    if m:
        return m.group("ap_name").strip(), "down"

    # Legacy nanny format fallback
    m = _NANNY_RE.search(raw)
    if m:
        return m.group("ap_name"), m.group("state").lower()

    return None


class _Handler(socketserver.BaseRequestHandler):
    server: "SyslogServer"

    def handle(self) -> None:
        try:
            raw = self.request[0].decode("utf-8", errors="replace").strip()
        except Exception:
            return

        result = _parse(raw)
        if not result:
            return

        ap_name, state = result
        source_ip = self.client_address[0]

        # ── Deduplication — one alert per AP per state per window ────────
        now = time.monotonic()
        key = (ap_name, state)
        with self.server.dedup_lock:
            last = self.server.dedup_cache.get(key, 0)
            if now - last < _DEDUP_WINDOW:
                log.debug("Suppressing duplicate event: AP %s → %s", ap_name, state.upper())
                # Still update state so the dashboard stays accurate
                self.server.state.add_ap_event(ap_name, state, source_ip)
                return
            self.server.dedup_cache[key] = now

        log.info("AP %s → %s  (src=%s)", ap_name, state.upper(), source_ip)

        # Register the AP in the persistent registry (no-op if already known)
        self.server.state.register_ap(ap_name, source_ip)

        # Determine previous state before updating
        was_down = self.server.state.ap_is_down.get(ap_name, None)
        self.server.state.add_ap_event(ap_name, state, source_ip)

        # Keep the persistent registry current
        self.server.state.update_ap_registry(ap_name, source_ip, is_down=(state == "down"))

        # Only email on DOWN events or recovery (UP after being DOWN)
        # Suppress routine heartbeat UP events for APs that were already up
        should_alert = (state == "down") or (state == "up" and was_down is True)
        if not should_alert:
            return

        icon = "DOWN" if state == "down" else "RECOVERED"
        self.server.notifier.send(
            f"[Aruba] AP {icon}: {ap_name}",
            (
                f"Access Point Status Change\n"
                f"==========================\n"
                f"AP Name : {ap_name}\n"
                f"Status  : {state.upper()}\n"
                f"Source  : {source_ip}\n"
                f"Raw msg : {raw}\n"
            ),
        )


class SyslogServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def __init__(
        self,
        host: str,
        port: int,
        notifier: EmailNotifier,
        state: AgentState,
    ) -> None:
        super().__init__((host, port), _Handler)
        self.notifier    = notifier
        self.state       = state
        self.dedup_cache: Dict[Tuple[str, str], float] = {}
        self.dedup_lock  = threading.Lock()


def _heartbeat_monitor(
    state: AgentState,
    notifier: EmailNotifier,
    timeout_minutes: int,
    check_interval: int,
    stop_event: threading.Event,
) -> None:
    """
    Runs in a background thread.
    Checks every *check_interval* seconds whether any known AP has not sent
    an 'Added AP' heartbeat within *timeout_minutes*.
    If so, marks it down and fires an alert — one alert per AP until it recovers.
    """
    log.info("AP heartbeat monitor started (timeout=%dm, check every %ds)",
             timeout_minutes, check_interval)
    while not stop_event.wait(check_interval):
        cutoff = datetime.now() - timedelta(minutes=timeout_minutes)
        stale  = state.get_stale_aps(cutoff)
        for ap_name, last_seen in stale.items():
            log.warning("AP heartbeat timeout: %s (last seen %s)", ap_name, last_seen)
            state.mark_ap_down(ap_name)
            state.update_ap_registry(ap_name, "heartbeat-timeout", is_down=True)
            notifier.send(
                f"[Aruba] AP DOWN (timeout): {ap_name}",
                (
                    f"Access Point Heartbeat Timeout\n"
                    f"==============================\n"
                    f"AP Name   : {ap_name}\n"
                    f"Status    : DOWN\n"
                    f"Last Seen : {last_seen.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"Timeout   : {timeout_minutes} minutes\n"
                    f"Note      : No 'Added AP' heartbeat received within the timeout window.\n"
                ),
            )


def start(
    cfg: configparser.ConfigParser,
    notifier: EmailNotifier,
    state: AgentState,
) -> None:
    host = cfg.get("syslog", "host", fallback="0.0.0.0")
    port = cfg.getint("syslog", "port", fallback=514)

    # How long without an 'Added AP' heartbeat before we flag the AP as down
    timeout_minutes = cfg.getint("syslog", "ap_timeout_minutes", fallback=10)
    # How often to check for stale APs (seconds)
    check_interval  = cfg.getint("syslog", "ap_check_interval",  fallback=60)

    srv = SyslogServer(host, port, notifier, state)
    threading.Thread(target=srv.serve_forever, name="syslog", daemon=True).start()
    log.info("Syslog listener on %s:%s/udp", host, port)

    # Start heartbeat monitor only if timeout is enabled (> 0)
    if timeout_minutes > 0:
        stop_event = threading.Event()
        threading.Thread(
            target=_heartbeat_monitor,
            args=(state, notifier, timeout_minutes, check_interval, stop_event),
            name="ap-heartbeat",
            daemon=True,
        ).start()
