"""
UDP Syslog listener — AP state change detection (AOS 8.10).

Parses incoming Conductor nanny messages and fires email alerts + state updates
for any AP that transitions UP or DOWN.
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

# Matches:  nanny[1234]: AP-floor2-office is now down
_NANNY_RE = re.compile(
    r"nanny(?:\[\d+\])?:\s+(?P<ap_name>\S+)\s+is\s+now\s+(?P<state>up|down)",
    re.IGNORECASE,
)


class _Handler(socketserver.BaseRequestHandler):
    server: "SyslogServer"

    def handle(self) -> None:
        try:
            raw = self.request[0].decode("utf-8", errors="replace").strip()
        except Exception:
            return

        match = _NANNY_RE.search(raw)
        if not match:
            return

        ap_name    = match.group("ap_name")
        state      = match.group("state").lower()
        source_ip  = self.client_address[0]

        log.info("AP %s → %s  (src=%s)", ap_name, state.upper(), source_ip)

        # Update shared state (visible in web UI)
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
    s    = cfg["syslog"] if "syslog" in cfg else {}
    host = s.get("host", "0.0.0.0")
    port = int(s.get("port", "514"))
    srv  = SyslogServer(host, port, notifier, state)
    threading.Thread(target=srv.serve_forever, name="syslog", daemon=True).start()
    log.info("Syslog listener on %s:%s/udp", host, port)
