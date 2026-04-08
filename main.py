#!/usr/bin/env python3
"""
Aruba All-in-One Agent — entry point.

Normal daemon mode:
  python main.py [/path/to/config.ini]

On-demand firmware update (interactive, exits when done):
  python main.py [/path/to/config.ini] --firmware-update
"""

import configparser
import logging
import os
import signal
import sys
import threading

# ── logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("aruba-agent")

# ── imports ─────────────────────────────────────────────────────────────────
from aruba_agent.notifier               import EmailNotifier
from aruba_agent.state                  import AgentState
from aruba_agent.scheduler              import Scheduler
from aruba_agent.monitors               import syslog, switch_poller
from aruba_agent.tasks.backup           import BackupTask
from aruba_agent.tasks.scanner          import NetworkScannerTask
from aruba_agent.tasks.arp              import ArpDiscoveryTask
from aruba_agent.tasks.firmware         import FirmwareUpdater
from aruba_agent.web.app                import create_app, start as start_web


# ── helpers ──────────────────────────────────────────────────────────────────

def load_config(path: str) -> configparser.ConfigParser:
    # inline_comment_prefixes lets '; comment' and '# comment' work on value lines
    cfg = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    if not cfg.read(path):
        log.warning("Config not found at %s — built-in defaults apply.", path)
    return cfg


def run_firmware_update(cfg: configparser.ConfigParser) -> None:
    cr = cfg["credentials"] if "credentials" in cfg else {}
    fw = cfg["firmware"]    if "firmware"    in cfg else {}

    ip_list_path = fw.get("ip_list", "/etc/aruba-agent/ip_list.txt")
    try:
        with open(ip_list_path) as f:
            ips = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        log.error("Firmware update: ip_list not found at %s", ip_list_path)
        sys.exit(1)

    FirmwareUpdater(
        ip_list        = ips,
        username       = cr.get("username", "admin"),
        password       = cr.get("password", ""),
        target_version = fw.get("target_version", ""),
        fw_image_path  = fw.get("image_path", ""),
        max_workers    = int(fw.get("max_workers", "2")),
    ).run()


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    args          = sys.argv[1:]
    firmware_mode = "--firmware-update" in args
    config_path   = next(
        (a for a in args if not a.startswith("--")),
        "/etc/aruba-agent/config.ini",
    )

    cfg      = load_config(config_path)
    state    = AgentState()
    notifier = EmailNotifier(cfg)

    # ── on-demand firmware update ────────────────────────────────────────────
    if firmware_mode:
        run_firmware_update(cfg)
        return

    # ── continuous monitors ──────────────────────────────────────────────────
    syslog.start(cfg, notifier, state)
    # Returns a manager — scanner will call manager.sync() after each discovery run
    manager = switch_poller.start_all(cfg, notifier, state)

    # ── scheduled tasks ──────────────────────────────────────────────────────
    scheduler = Scheduler()

    # Config backup
    backup_task = None
    if cfg.getboolean("backup", "enabled", fallback=False):
        backup_task = BackupTask(cfg, notifier, state)
        scheduler.add(cfg.get("backup", "schedule", fallback="02:00"), backup_task.run)

    # Network scanner — pass the monitor manager so new switches get polled automatically
    scanner_task = None
    if cfg.getboolean("scanner", "enabled", fallback=False):
        scanner_task = NetworkScannerTask(cfg, notifier, state, monitor_manager=manager)
        scheduler.add(cfg.get("scanner", "schedule", fallback="00:00"), scanner_task.run)

    # ARP discovery — one task per [arp.<location>] section
    for sec in cfg.sections():
        if not sec.startswith("arp."):
            continue
        if not cfg.getboolean(sec, "enabled", fallback=True):
            continue
        name     = sec[len("arp."):]
        arp_task = ArpDiscoveryTask(name, cfg[sec], cfg["credentials"] if "credentials" in cfg else {}, state)
        scheduler.add(cfg.get(sec, "schedule", fallback="01:00"), arp_task.run)

    scheduler.start()

    # ── web UI ───────────────────────────────────────────────────────────────
    web_cfg  = cfg["web"] if "web" in cfg else {}
    web_host = web_cfg.get("host", "0.0.0.0")
    web_port = int(web_cfg.get("port", "8080"))
    flask_app = create_app(
        state,
        backup_fn  = backup_task.run  if backup_task  else None,
        scanner_fn = scanner_task.run if scanner_task else None,
        cfg        = cfg,
    )
    start_web(flask_app, host=web_host, port=web_port)

    # ── graceful shutdown ────────────────────────────────────────────────────
    stop_event = threading.Event()

    def _shutdown(signum, _frame) -> None:
        log.info("Signal %s received — shutting down gracefully", signum)
        scheduler.stop()
        manager.stop_all()
        stop_event.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    log.info("Aruba agent running (PID %d)", os.getpid())
    stop_event.wait()
    log.info("Aruba agent stopped cleanly")


if __name__ == "__main__":
    main()
