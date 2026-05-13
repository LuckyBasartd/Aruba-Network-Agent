#!/usr/bin/env python3
"""
Aruba All-in-One Agent — entry point.

Normal daemon mode:
  python main.py [/path/to/config.ini]

On-demand firmware update (interactive, exits when done):
  python main.py [/path/to/config.ini] --firmware-update

Verify all backup files against their SHA-256 sidecars (exits 0 if all
match, 2 if any corruption is found — fit for cron):
  python main.py [/path/to/config.ini] --verify-backups

Decrypt a single backup file to stdout for restore:
  python main.py [/path/to/config.ini] --decrypt-backup /var/lib/aruba-agent/backups/<host>/<file>.cfg.enc > restored.cfg
"""

import configparser
import logging
import os
import signal
import sys
import threading
import warnings
from typing import Dict, Optional


# ── third-party warning suppression ─────────────────────────────────────────
# pysnmp 6.x's AES priv path imports
# cryptography.hazmat.primitives.ciphers.modes.CFB. cryptography 45+
# moved CFB to the 'decrepit' submodule and emits a
# CryptographyDeprecationWarning every time the old path is touched.
# That fires on every SNMPv3 priv decrypt — at fleet scale (~200
# switches × 30s polls), several warnings per second flood journald
# and drown every other log line. Until pysnmp upstream switches to
# the new import, suppress the warning here so the journal stays
# usable. The actual cryptographic operation is unchanged.
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except ImportError:
    # Fallback: filter by message + module if the class isn't importable
    warnings.filterwarnings("ignore", message=r".*CFB has been moved.*")
    warnings.filterwarnings(
        "ignore", category=DeprecationWarning, module=r"pysnmpcrypto.*",
    )

# ── logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("aruba-agent")


# ── unhandled-exception capture ─────────────────────────────────────────────
# When a worker thread (waitress, switch monitor, scheduler) dies from an
# unhandled exception, Python's default behavior is to print the traceback
# to stderr — which systemd captures, but journald can rotate it away
# before the operator notices the symptom. Route thread exceptions
# through our regular logger so they stay in the journal alongside the
# rest of the agent's output, with %(asctime)s prefixes that survive a
# fleet-scale incident.
def _thread_exception_hook(args) -> None:
    thread_name = args.thread.name if args.thread is not None else "<unknown>"
    log.error(
        "Unhandled exception in thread %s — thread is now dead:",
        thread_name,
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
    )

threading.excepthook = _thread_exception_hook


def _process_exception_hook(exc_type, exc_value, exc_traceback) -> None:
    """Mirror of the thread hook for the main thread."""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    log.error(
        "Unhandled exception on the main thread:",
        exc_info=(exc_type, exc_value, exc_traceback),
    )

sys.excepthook = _process_exception_hook

# ── imports ─────────────────────────────────────────────────────────────────
from aruba_agent                        import secrets_store
from aruba_agent.audit                   import audit, DEFAULT_AUDIT_LOG_PATH
from aruba_agent.notifier               import EmailNotifier
from aruba_agent.snmp                   import from_config as build_snmp_agent
from aruba_agent.state                  import AgentState
from aruba_agent.scheduler              import Scheduler
from aruba_agent.monitors               import switch_poller
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
        # Password may be encrypted-at-rest in v3.0.1+ configs.
        password       = secrets_store.decrypt(cr.get("password", "")),
        target_version = fw.get("target_version", ""),
        fw_image_path  = fw.get("image_path", ""),
        max_workers    = int(fw.get("max_workers", "2")),
    ).run()


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    args          = sys.argv[1:]
    firmware_mode = "--firmware-update" in args
    verify_mode   = "--verify-backups" in args
    # --decrypt-backup <path> is a two-token flag; the next positional
    # is the backup file path. Extract it now so the path doesn't get
    # mis-parsed as config_path below.
    decrypt_path: Optional[str] = None
    if "--decrypt-backup" in args:
        idx = args.index("--decrypt-backup")
        if idx + 1 >= len(args):
            print("--decrypt-backup needs a path argument", file=sys.stderr)
            sys.exit(2)
        decrypt_path = args[idx + 1]
        # Strip the flag + its value so the positional config-path
        # filter below sees a clean argv.
        args = args[:idx] + args[idx + 2:]

    config_path   = next(
        (a for a in args if not a.startswith("--")),
        "/etc/aruba-agent/config.ini",
    )

    cfg      = load_config(config_path)

    # T2.2: --verify-backups CLI subcommand.
    # Walks the configured backup_path, recomputes SHA-256 for every
    # .cfg, compares against its .sha256 sidecar, and exits non-zero
    # if any mismatches surface. Designed for cron / monitoring.
    # Runs BEFORE the secrets bootstrap so a missing master key
    # doesn't block backup verification on a recovery host.
    if verify_mode:
        from aruba_agent.tasks.backup import verify_backups
        backup_path = cfg.get(
            "backup", "backup_path",
            fallback="/var/lib/aruba-agent/backups",
        )
        ok, bad, bad_paths = verify_backups(backup_path)
        print(f"verify_backups: {ok} OK, {bad} corrupt")
        for p in bad_paths:
            print(f"  CORRUPT: {p}")
        sys.exit(0 if bad == 0 else 2)

    # ── secrets bootstrap ────────────────────────────────────────────────────
    # NOTE: --decrypt-backup needs this bootstrap to run BEFORE it
    # invokes decrypt_backup(). Both fall through to the normal
    # bootstrap block below.
    # v3.0.1: every sensitive config field (passwords, RADIUS secret,
    # SNMP auth/priv passphrases, secret_key) is stored encrypted at
    # rest with a Fernet master key. We initialise the SecretManager
    # BEFORE anything else reads config, then run the auto-migration
    # so any cleartext values from a v3.0.0 install get encrypted
    # in-place on first start. The migration is idempotent — once
    # everything is enc:..., it's a no-op.
    master_key_path = cfg.get(
        "agent", "master_key_file",
        fallback=secrets_store.DEFAULT_MASTER_KEY_PATH,
    )
    try:
        sm = secrets_store.SecretManager(master_key_path)
        secrets_store.install(sm)
    except Exception as exc:
        log.error(
            "Could not initialise secret manager at %s: %s. "
            "Passwords in config.ini will be read as cleartext.",
            master_key_path, exc,
        )
    else:
        try:
            changed = secrets_store.migrate_config(config_path, sm)
            if changed:
                log.info("Encrypted %d cleartext field(s) in %s",
                         len(changed), config_path)
                # Reparse the config so downstream readers see the
                # encrypted forms — the in-memory cfg above still
                # holds the cleartext values from before the migration.
                cfg = load_config(config_path)
        except Exception as exc:
            log.error("Config migration failed (%s) — continuing with "
                      "what's already loaded", exc)

    # ── --decrypt-backup ────────────────────────────────────────────────────
    # Runs after the secrets bootstrap (so the SecretManager is loaded)
    # but before the rest of the agent comes up. Writes plaintext to
    # stdout so the operator can pipe it anywhere:
    #     ... --decrypt-backup file.cfg.enc > restored.cfg
    # Exits non-zero with a useful error on missing key / wrong key.
    if decrypt_path is not None:
        from aruba_agent.tasks.backup import decrypt_backup
        try:
            plaintext = decrypt_backup(decrypt_path)
        except RuntimeError as exc:
            print(f"--decrypt-backup: {exc}", file=sys.stderr)
            sys.exit(2)
        # Write raw bytes to stdout; -- avoids encoding issues if the
        # config file happens to be UTF-8 with line endings that
        # differ from the OS.
        sys.stdout.buffer.write(plaintext)
        sys.exit(0)

    # Audit log — append-only file separate from journald.
    # Operator-controllable path with the same [agent] block as the
    # state file and master key. Failures are non-fatal: audit.install
    # logs a warning and falls back to journal-only on permission
    # errors.
    audit_log_path = cfg.get(
        "agent", "audit_log_file",
        fallback=DEFAULT_AUDIT_LOG_PATH,
    )
    audit.install(audit_log_path)
    log.info("Audit log: %s", audit.path or "(disabled — could not open file)")

    # State persistence — survives agent restarts and host reboots.
    # Default lives alongside the rest of the runtime data under
    # /var/lib/aruba-agent/. Override via [agent] state_file = ...
    state_file = cfg.get(
        "agent", "state_file",
        fallback="/var/lib/aruba-agent/state.json",
    )
    state    = AgentState(snapshot_path=state_file)
    notifier = EmailNotifier(cfg)

    # ── on-demand firmware update ────────────────────────────────────────────
    if firmware_mode:
        run_firmware_update(cfg)
        return

    # SNMPv3 agent — None when [snmp] is missing or disabled.
    # When present, the switch poller uses it for reachability instead
    # of opening a REST session every 30s.
    snmp_agent = build_snmp_agent(cfg)

    # Vendor detector — only useful when SNMP is configured. Identifies
    # each switch's vendor by sysObjectID on first reachable poll and
    # caches the result on SwitchState.
    detector = None
    if snmp_agent is not None:
        from aruba_agent.drivers.detector import VendorDetector
        detector = VendorDetector(snmp_agent)

    # ── continuous monitors ──────────────────────────────────────────────────
    # Returns a manager — scanner will call manager.sync() after each discovery run
    manager = switch_poller.start_all(
        cfg, notifier, state,
        snmp     = snmp_agent,
        detector = detector,
    )

    # Pre-seed the manager from the existing ip_list.txt so all previously
    # discovered switches are monitored immediately on startup without waiting
    # for the next scheduled scan.
    _ip_list_path = cfg.get("scanner", "ip_list_output",
                            fallback="/var/lib/aruba-agent/ip_list.txt")
    try:
        with open(_ip_list_path) as _f:
            _existing_ips = [l.strip() for l in _f if l.strip() and not l.startswith("#")]
        if _existing_ips:
            log.info("Pre-seeding monitor manager with %d IPs from %s",
                     len(_existing_ips), _ip_list_path)
            manager.sync(_existing_ips)
    except FileNotFoundError:
        log.info("No existing ip_list found at %s — waiting for first scan", _ip_list_path)

    # v3.0.3: pre-seed with manually-added hosts (Settings → Manual Hosts).
    # These live outside the scanner's subnets so manager.sync() will
    # never bring them back if removed. Each carries its operator-chosen
    # monitor_mode so the SwitchMonitor knows whether to ping, SNMP,
    # or do the whole stack.
    from aruba_agent.manual_hosts import ManualHostsStore
    _manual_hosts_path = cfg.get(
        "agent", "manual_hosts_file",
        fallback="/var/lib/aruba-agent/manual_hosts.json",
    )
    _manual_store = ManualHostsStore(_manual_hosts_path)
    _manual_list = _manual_store.list_hosts()
    if _manual_list:
        log.info("Pre-seeding monitor manager with %d manual host(s) from %s",
                 len(_manual_list), _manual_hosts_path)
        for _h in _manual_list:
            manager.add(
                host         = _h["host"],
                name         = _h["name"],
                monitor_mode = _h.get("monitor_mode", "auto"),
            )
            # Honour a per-host SNMP profile pin if the operator set one.
            if _h.get("snmp_profile"):
                state.set_switch_profile(_h["name"], _h["snmp_profile"])

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

    # ARP discovery — one task per [arp.<location>] section. We also
    # accumulate a dict of name → run() callables so the web UI can
    # offer a per-location Run Now button (mirroring the scanner /
    # backup triggers).
    arp_fns: Dict[str, callable] = {}
    for sec in cfg.sections():
        if not sec.startswith("arp."):
            continue
        if not cfg.getboolean(sec, "enabled", fallback=True):
            continue
        name     = sec[len("arp."):]
        arp_task = ArpDiscoveryTask(
            name, cfg[sec],
            cfg["credentials"]       if "credentials"       in cfg else {},
            state,
            cisco_creds  = cfg["credentials.cisco"]  if "credentials.cisco"  in cfg else None,
            arista_creds = cfg["credentials.arista"] if "credentials.arista" in cfg else None,
        )
        scheduler.add(cfg.get(sec, "schedule", fallback="01:00"), arp_task.run)
        arp_fns[name] = arp_task.run

    scheduler.start()

    # ── web UI ───────────────────────────────────────────────────────────────
    web_cfg     = cfg["web"] if "web" in cfg else {}
    web_host    = web_cfg.get("host", "0.0.0.0")
    web_port    = int(web_cfg.get("port", "8080"))
    # Default 16 — comfortable headroom on a 200-switch fleet. The C6.x
    # SwitchMonitor pool can keep the GIL busy under load; waitress
    # needs enough workers to slip dashboard requests through.
    web_threads = int(web_cfg.get("threads", "16"))
    flask_app = create_app(
        state,
        backup_fn         = backup_task.run  if backup_task  else None,
        scanner_fn        = scanner_task.run if scanner_task else None,
        arp_fns           = arp_fns,
        cfg               = cfg,
        cfg_path          = config_path,
        snmp_agent        = snmp_agent,
        monitor_manager   = manager,
        manual_hosts_path = _manual_hosts_path,
    )
    start_web(flask_app, host=web_host, port=web_port, threads=web_threads)

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
