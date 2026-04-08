"""
UDP Syslog listener — AP state change detection (AOS 8.10).

Handles Aruba CEF (Common Event Format) syslog messages from the
Mobility Conductor / Mobility Director.

CEF message format received:
  CEF:0|Aruba|A92xx|...|msg=<400168> <pid> <NOTI> \|stm\|  Added AP <MAC>-<AP-Name>
  CEF:0|Aruba|A92xx|...|msg=<400169> <pid> <NOTI> \|stm\|  Deleted AP <MAC>-<AP-Name>

AP name is extracted from the MAC-APName string at the end of the msg field.
Also handles legacy plain-syslog nanny format as a fallback.
"""

from __future__ import annotations

import configparser
import logging
import re
import socketserver
import threading

from aruba_agent.notifier import EmailNotifier
from aruba_agent.state    import AgentState

log = logging.getLogger(__name__)

# ── CEF parser ───────────────────────────────────────────────────────────────
# Matches the msg= field value from a CEF syslog line
_CEF_MSG_RE = re.compile(r"msg=(?P<msg>.+)$")

# Matches "Added AP" or "Deleted AP" followed by MAC-APName
# MAC format: xx:xx:xx:xx:xx:xx  then  -  then AP name (rest of string)
_STM_AP_RE = re.compile(
    r"(?P<action>Added|Deleted)\s+AP\s+"
    r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}-(?P<ap_name>\S+)",
    re.IGNORECASE,
)

# ── Legacy plain-syslog fallback ─────────────────────────────────────────────
# Matches:  nanny[1234]: AP-floor2-office is now down
_NANNY_RE = re.compile(
    r"nanny(?:\[\d+\])?:\s+(?P<ap_name>\S+)\s+is\s+now\s+(?P<state>up|down)",
    re.IGNORECASE,
)


def _parse(raw: str) -> tuple[str, str] | None:
    """
    Returns (ap_name, state) or None if the message is not an AP event.
    state is 'up' or 'down'.
    """
    # ── Try CEF format first ──────────────────────────────────────────────
    if "CEF:" in raw:
        msg_match = _CEF_MSG_RE.search(raw)
        if msg_match:
            msg = msg_match.group("msg")
            ap_match = _STM_AP_RE.search(msg)
            if ap_match:
                action  = ap_match.group("action").lower()
                ap_name = ap_match.group("ap_name").strip()
                state   = "up" if action == "added" else "down"
                return ap_name, state

    # ── Fallback: legacy nanny format ────────────────────────────────────
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

        log.info("AP %s → %s  (src=%s)", ap_name, state.upper(), source_ip)
        self.server.state.add_ap_event(ap_name, state, source_ip)

        icon = "DOWN" if state == "down" else "UP"
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
        self.notifier = notifier
        self.state    = state


def start(
    cfg: configparser.ConfigParser,
    notifier: EmailNotifier,
    state: AgentState,
) -> None:
    host = cfg.get("syslog", "host", fallback="0.0.0.0")
    port = cfg.getint("syslog", "port", fallback=514)
    srv  = SyslogServer(host, port, notifier, state)
    threading.Thread(target=srv.serve_forever, name="syslog", daemon=True).start()
    log.info("Syslog listener on %s:%s/udp", host, port)
