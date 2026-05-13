"""
Config Backup Task — ported from Aruba_Switch_Backup.py.

Loops through ip_list, saves running-config → startup-config on each switch,
downloads the binary, stores it locally with rolling retention, then emails
a summary report and updates AgentState.
"""

from __future__ import annotations

import configparser
import glob
import hashlib
import logging
import os
from datetime import datetime
from typing import List, Tuple

from aruba_agent              import secrets_store
from aruba_agent.drivers       import driver_for
from aruba_agent.notifier      import EmailNotifier
from aruba_agent.secrets_store import decrypt as _decrypt
from aruba_agent.state         import AgentState

log = logging.getLogger(__name__)


class BackupTask:
    def __init__(
        self,
        cfg: configparser.ConfigParser,
        notifier: EmailNotifier,
        state: AgentState,
    ) -> None:
        b  = cfg["backup"]      if "backup"      in cfg else {}
        cr = cfg["credentials"] if "credentials" in cfg else {}
        self.ip_list_path = b.get("ip_list",     "/etc/aruba-agent/ip_list.txt")
        self.backup_path  = b.get("backup_path", "/var/lib/aruba-agent/backups")
        self.retention    = int(b.get("retention_days", "7"))
        self.username     = cr.get("username", "admin")
        # Passwords / enable secrets are decrypted at read time so the
        # rest of the task (driver_for, NAPALM) sees cleartext as it
        # always has. Cleartext values pass through unchanged for
        # back-compat with un-migrated configs.
        self.password     = _decrypt(cr.get("password", ""))
        self.api_version  = b.get("api_version") or None   # None → auto-detect

        # Per-vendor overrides. Blank values fall through to the
        # default username / password above so a single-credential
        # shop doesn't need to fill them in twice.
        cc = cfg["credentials.cisco"]  if "credentials.cisco"  in cfg else {}
        self.cisco_username = (cc.get("username", "") or "").strip()
        self.cisco_password = _decrypt(cc.get("password", ""))
        self.cisco_enable   = _decrypt(cc.get("enable_secret", ""))
        self.cisco_napalm   = (cc.get("napalm_driver", "ios") or "ios").strip()
        # v3.0.3: optional SSH key file for Cisco. When set, the
        # password becomes the key's passphrase ("" for unencrypted).
        self.cisco_key_file = (cc.get("key_file", "") or "").strip()

        ac = cfg["credentials.arista"] if "credentials.arista" in cfg else {}
        self.arista_username = (ac.get("username", "") or "").strip()
        self.arista_password = _decrypt(ac.get("password", ""))
        self.arista_enable   = _decrypt(ac.get("enable_password", ""))
        self.arista_transport = (ac.get("transport", "https") or "https").strip()
        try:
            self.arista_port = int(ac.get("port", "")) if (ac.get("port", "") or "").strip() else None
        except ValueError:
            self.arista_port = None

        self.notifier     = notifier
        self.state        = state

    def _load_ips(self) -> List[str]:
        try:
            with open(self.ip_list_path) as f:
                return [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            log.error("Backup: ip_list not found at %s", self.ip_list_path)
            return []

    def _cleanup(self, host_dir: str, hostname: str) -> None:
        # Glob both legacy .cfg and v3.0.4 .cfg.enc files. A site upgrading
        # in place will have a mix until retention rotates the cleartext
        # generation out — both shapes are retention-eligible.
        patterns = (
            f"{hostname}-startup-config-*.cfg",
            f"{hostname}-startup-config-*.cfg.enc",
        )
        all_files = []
        for pat in patterns:
            all_files.extend(glob.glob(os.path.join(host_dir, pat)))
        files = sorted(all_files, key=os.path.getmtime)
        for old in files[: -self.retention]:
            try:
                os.remove(old)
                log.info("Backup: removed old file %s", os.path.basename(old))
            except OSError as exc:
                log.warning("Backup: could not remove %s: %s", old, exc)
            # Pair-delete the .sha256 sidecar so orphans don't accumulate.
            sidecar = old + ".sha256"
            if os.path.exists(sidecar):
                try:
                    os.remove(sidecar)
                except OSError as exc:
                    log.warning("Backup: could not remove sidecar %s: %s",
                                sidecar, exc)

    def run(self) -> None:
        log.info("Backup task started")
        ips = self._load_ips()
        if not ips:
            return

        success: List[dict] = []
        failed:  List[dict] = []

        skipped_modes = 0
        for ip in ips:
            hostname = "N/A"
            # v3.0.3: respect the per-host monitor_mode. Hosts marked
            # as "icmp" or "snmp_ro" don't grant the agent the access
            # it needs to read running-config, so skip them silently
            # rather than fill the FAILED panel with noise about hosts
            # that were never expected to back up.
            mode = self.state.get_mode_for_host(ip)
            if mode in ("icmp", "snmp_ro"):
                log.debug("Backup: skipping %s — monitor_mode=%s "
                          "(no write access)", ip, mode)
                skipped_modes += 1
                continue

            # Per-host vendor lookup. The C3 detector populates
            # SwitchState.vendor on the first reachable SNMPv3 poll;
            # we use that here so Aruba switches go through the
            # AOS-CX REST path (unchanged) and Cisco switches go
            # through NAPALM via SSH automatically. Empty / unknown
            # vendors default to the AOS-CX driver, preserving v2.x
            # behavior.
            vendor = self.state.get_vendor_for_host(ip) or None
            try:
                with driver_for(
                    ip, self.username, self.password,
                    preferred_version       = self.api_version,
                    vendor_hint             = vendor,
                    cisco_username          = self.cisco_username,
                    cisco_password          = self.cisco_password,
                    cisco_enable            = self.cisco_enable,
                    cisco_napalm_driver     = self.cisco_napalm,
                    cisco_key_file          = self.cisco_key_file,
                    arista_username         = self.arista_username,
                    arista_password         = self.arista_password,
                    arista_enable_password  = self.arista_enable,
                    arista_transport        = self.arista_transport,
                    arista_port             = self.arista_port,
                ) as drv:
                    if not drv.logged_in:
                        failed.append({"ip": ip, "hostname": hostname,
                                       "issue": f"Login failed ({drv.vendor}): "
                                                f"{drv.error}"})
                        continue

                    # Prefer the hostname state already knows for this
                    # IP (set by switch_poller via SNMP sysName.0).
                    # That keeps the on-disk directory in sync with
                    # what the dashboard renders, so the "click row
                    # → show backups" modal can find the file.
                    # NAPALM's get_hostname() for Cisco / Arista
                    # returns the short hostname while SNMP sysName
                    # often includes the domain — using the driver's
                    # value would put files under a name the
                    # dashboard never asks for.
                    hostname = (
                        self.state.get_hostname_for_host(ip)
                        or drv.get_hostname()
                        or "unknown"
                    )

                    if not drv.save_running_to_startup():
                        failed.append({"ip": ip, "hostname": hostname,
                                       "issue": f"Save running→startup failed "
                                                f"({drv.vendor}): {drv.error}"})
                        continue

                    data = drv.get_running_config()
                    if not data:
                        failed.append({"ip": ip, "hostname": hostname,
                                       "issue": f"Config download failed "
                                                f"({drv.vendor}): {drv.error}"})
                        continue

                # Write outside the with-block so logout happens first
                host_dir = os.path.join(self.backup_path, hostname)
                os.makedirs(host_dir, exist_ok=True)
                ts    = datetime.now().strftime("%Y-%m-%d_%H%M%S")

                # T3.1: encrypt the config blob at rest if a master key
                # is available. Switch configs contain ACLs, VLAN
                # secrets, BGP keys, SSH banners, sometimes the
                # operator's RADIUS shared secret — a stolen
                # /var/lib/aruba-agent/backups/ tarball would otherwise
                # be a fleet-wide credential leak. We reuse the
                # existing Fernet master key (managed by secrets_store)
                # rather than introducing a second key to back up.
                #
                # File extension is .cfg.enc when ciphertext, .cfg when
                # cleartext, so the on-disk shape is obvious without
                # reading the file. The SHA-256 sidecar covers
                # whatever bytes actually land on disk — verify_backups
                # checks file integrity, not plaintext integrity.
                sm = secrets_store.get()
                if sm is not None:
                    # Fernet wants str input. Encode bytes → str via
                    # the Fernet-internal helper by calling
                    # ._fernet.encrypt(data) directly; secrets_store
                    # only exposes string encrypt(). Use the raw token.
                    try:
                        ciphertext = sm._fernet.encrypt(data)
                    except Exception as exc:
                        # If encryption ever fails, refuse to silently
                        # write cleartext — that's the surprise we're
                        # trying to prevent.
                        failed.append({"ip": ip, "hostname": hostname,
                                       "issue": f"Encryption failed: {exc}"})
                        log.error("Backup encryption failed for %s: %s",
                                  hostname, exc)
                        continue
                    fpath = os.path.join(
                        host_dir,
                        f"{hostname}-startup-config-{ts}.cfg.enc",
                    )
                    on_disk = ciphertext
                else:
                    # No master key: fall back to cleartext, but warn.
                    # This is the path a v3.0.0 install without the
                    # encryption layer takes; we don't want to refuse
                    # the backup, just make the limitation visible.
                    log.warning(
                        "Backup: no master key — writing %s in CLEARTEXT. "
                        "Configure /etc/aruba-agent/master.key to enable "
                        "at-rest encryption.", hostname,
                    )
                    fpath = os.path.join(
                        host_dir,
                        f"{hostname}-startup-config-{ts}.cfg",
                    )
                    on_disk = data

                with open(fpath, "wb") as f:
                    f.write(on_disk)

                # T2.2: SHA-256 sidecar of whatever bytes hit disk.
                # If the file is encrypted, the sidecar covers the
                # ciphertext — bit-rot detection still works without
                # the master key being available.
                digest = hashlib.sha256(on_disk).hexdigest()
                sidecar = fpath + ".sha256"
                with open(sidecar, "w", encoding="ascii") as f:
                    f.write(f"{digest}  {os.path.basename(fpath)}\n")
                self._cleanup(host_dir, hostname)
                success.append({"ip": ip, "hostname": hostname})
                log.info("Backup OK: %s (%s)%s",
                         hostname, ip, " [encrypted]" if sm else " [cleartext]")

            except Exception as exc:
                # Belt-and-braces: drivers already scrub their own
                # error fields, but anything that escapes here is
                # bound for the dashboard's "FAILED" panel and the
                # nightly email report. Strip credentials defensively.
                msg = secrets_store.redact(str(exc))
                failed.append({"ip": ip, "hostname": hostname, "issue": msg})
                log.error("Backup error for %s: %s", ip, msg)

        self.state.set_backup_result(len(success), len(failed), failed)
        self._send_report(success, failed)
        log.info("Backup task done: %d ok, %d failed, %d skipped (icmp/snmp_ro)",
                 len(success), len(failed), skipped_modes)

    def _send_report(self, success: List[dict], failed: List[dict]) -> None:
        now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body = (
            f"Aruba CX Config Backup — {now}\n"
            f"Total: {len(success)+len(failed)}  |  OK: {len(success)}  |  Failed: {len(failed)}\n"
        )
        if success:
            body += "\nSUCCESSFUL:\n"
            body += "\n".join(f"  {s['ip']:16s}  {s['hostname']}" for s in success)
        if failed:
            body += "\n\nFAILED:\n"
            body += "\n".join(
                f"  {f['ip']:16s}  {f['hostname']:24s}  {f['issue']}" for f in failed
            )
        self.notifier.send(
            f"[Aruba] Config Backup Report — {datetime.now().strftime('%Y-%m-%d')}",
            body,
        )


# ─── verify subcommand ───────────────────────────────────────────────────────

def verify_backups(backup_root: str) -> Tuple[int, int, List[str]]:
    """
    Walk ``backup_root``, recompute SHA-256 for every ``.cfg`` file, and
    compare against its ``.sha256`` sidecar. Returns (ok_count,
    bad_count, bad_paths).

    Files that don't have a sidecar (older backups from before T2.2)
    are reported as "missing" but not counted as bad — they pre-date
    the checksum behaviour and there's nothing to compare against.
    Operators can re-run the backup task to generate sidecars going
    forward.

    Designed to be called from main.py's ``--verify-backups`` CLI so
    operators can integrate this into cron / monitoring without
    importing the agent.
    """
    ok    = 0
    bad   = 0
    bad_paths: List[str] = []
    missing = 0

    if not os.path.isdir(backup_root):
        log.error("verify_backups: %s is not a directory", backup_root)
        return (0, 0, [])

    for dirpath, _dirnames, filenames in os.walk(backup_root):
        for fn in filenames:
            # Cover both legacy cleartext (.cfg) and T3.1 ciphertext
            # (.cfg.enc) backups. The SHA-256 sidecar is computed over
            # whatever bytes hit disk, so we don't need the master key
            # to verify integrity — operators can integrity-check a
            # backup tarball on a recovery host that doesn't have the
            # master key at all.
            if not (fn.endswith(".cfg") or fn.endswith(".cfg.enc")):
                continue
            cfg_path = os.path.join(dirpath, fn)
            side_path = cfg_path + ".sha256"
            if not os.path.exists(side_path):
                missing += 1
                continue
            try:
                # Read the expected digest. sha256sum format is
                # "<hex>  <basename>" — we only care about the hex.
                with open(side_path, "r", encoding="ascii") as f:
                    expected = f.read().strip().split()[0].lower()
                # Recompute. Files are typically <1 MB so we read in
                # one shot; chunked read would matter only for huge
                # configs which AOS-CX caps at ~10 MB anyway.
                with open(cfg_path, "rb") as f:
                    actual = hashlib.sha256(f.read()).hexdigest()
            except (OSError, IndexError) as exc:
                log.error("verify_backups: could not check %s: %s", cfg_path, exc)
                bad += 1
                bad_paths.append(cfg_path)
                continue
            if expected != actual:
                log.error("verify_backups: MISMATCH %s "
                          "(expected %s, got %s)",
                          cfg_path, expected, actual)
                bad += 1
                bad_paths.append(cfg_path)
            else:
                ok += 1

    log.info("verify_backups: %d ok, %d bad, %d without sidecar in %s",
             ok, bad, missing, backup_root)
    return (ok, bad, bad_paths)


def decrypt_backup(path: str) -> bytes:
    """
    Return the plaintext of an encrypted backup file. Used by
    ``main.py --decrypt-backup`` for restore workflows. Files ending
    in ``.cfg`` are assumed to be legacy cleartext and returned as-is.

    Raises ``RuntimeError`` with a useful message on:
      * missing file
      * missing master key (caller can't decrypt)
      * malformed ciphertext
    """
    if not os.path.exists(path):
        raise RuntimeError(f"Backup file not found: {path}")

    with open(path, "rb") as f:
        raw = f.read()

    if path.endswith(".cfg") and not path.endswith(".cfg.enc"):
        # Legacy cleartext — return as-is.
        return raw

    sm = secrets_store.get()
    if sm is None:
        raise RuntimeError(
            f"{path} is encrypted but no master key is loaded. "
            "Configure /etc/aruba-agent/master.key (or pass "
            "--config so the agent can find it)."
        )
    try:
        # sm._fernet is the same Fernet instance used to encrypt.
        return sm._fernet.decrypt(raw)
    except Exception as exc:
        raise RuntimeError(
            f"Could not decrypt {path}: {exc}. "
            "Wrong master key, corrupted file, or a backup that "
            "predates this master.key."
        ) from exc
