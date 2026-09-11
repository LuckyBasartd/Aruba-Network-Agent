"""
Config change detection + diffing (SolarWinds "config change" parity).

Works entirely off the existing versioned, encrypted backups produced by
tasks/backup.py (`<backup_root>/<hostname>/<hostname>-startup-config-<ts>.cfg[.enc]`).

IMPORTANT: backups are Fernet-encrypted, and Fernet is non-deterministic — the
`.sha256` sidecars are computed over ciphertext, so two backups of an identical
config have different sidecars. Change detection therefore compares the
**decrypted plaintext**, never the sidecars.

Everything decrypts in memory (via tasks.backup.decrypt_backup); plaintext never
lands on disk.
"""

from __future__ import annotations

import difflib
import logging
import os
from typing import List, Optional

log = logging.getLogger(__name__)

_SUFFIXES = (".cfg", ".cfg.enc")


def list_versions(backup_root: str, hostname: str) -> List[str]:
    """Backup filenames for a host, newest first."""
    d = os.path.join(backup_root, hostname)
    if not os.path.isdir(d):
        return []
    return sorted([f for f in os.listdir(d) if f.endswith(_SUFFIXES)], reverse=True)


def read_text(backup_root: str, hostname: str, filename: str) -> Optional[str]:
    """Decrypt a backup version to text (in memory). None on any failure."""
    from aruba_agent.tasks.backup import decrypt_backup
    path = os.path.join(backup_root, hostname, filename)
    try:
        return decrypt_backup(path).decode("utf-8", errors="replace")
    except Exception as exc:
        log.warning("config_diff: could not read %s/%s (%s)", hostname, filename, exc)
        return None


def unified(old_text: str, new_text: str,
            fromfile: str = "previous", tofile: str = "current") -> str:
    """Unified diff between two config texts (pure; easy to unit-test)."""
    lines = difflib.unified_diff(
        old_text.splitlines(), new_text.splitlines(),
        fromfile=fromfile, tofile=tofile, lineterm="",
    )
    return "\n".join(lines)


def diff_versions(backup_root: str, hostname: str, a: str, b: str) -> Optional[str]:
    """Unified diff between two named versions (a = older, b = newer)."""
    ta = read_text(backup_root, hostname, a)
    tb = read_text(backup_root, hostname, b)
    if ta is None or tb is None:
        return None
    return unified(ta, tb, a, b)


def _count(diff: str) -> tuple:
    added = sum(1 for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff.splitlines() if l.startswith("-") and not l.startswith("---"))
    return added, removed


def changed_since_previous(backup_root: str, hostname: str) -> Optional[dict]:
    """Compare the two newest versions for a host.

    Returns None when there are <2 versions or a read fails; otherwise a dict
    with changed/added/removed/diff (diff empty when unchanged)."""
    vers = list_versions(backup_root, hostname)
    if len(vers) < 2:
        return None
    curr, prev = vers[0], vers[1]
    tc = read_text(backup_root, hostname, curr)
    tp = read_text(backup_root, hostname, prev)
    if tc is None or tp is None:
        return None
    if tc == tp:
        return {"hostname": hostname, "prev": prev, "curr": curr,
                "changed": False, "added": 0, "removed": 0, "diff": ""}
    diff = unified(tp, tc, prev, curr)
    added, removed = _count(diff)
    return {"hostname": hostname, "prev": prev, "curr": curr,
            "changed": True, "added": added, "removed": removed, "diff": diff}


def detect_changes(backup_root: str, hostnames) -> List[dict]:
    """Return change records for hosts whose newest config differs from the prior."""
    out: List[dict] = []
    seen = set()
    for h in hostnames:
        if not h or h in seen:
            continue
        seen.add(h)
        rec = changed_since_previous(backup_root, h)
        if rec and rec["changed"]:
            out.append(rec)
    return out


def format_change_email(changes: List[dict], max_lines_per_device: int = 80) -> str:
    """Build the coalesced 'config changed' email body from change records."""
    lines: List[str] = []
    lines.append(f"Configuration changes detected on {len(changes)} device(s) "
                 f"in the latest backup:\n")
    for c in sorted(changes, key=lambda r: r["hostname"]):
        lines.append(f"  {c['hostname']:<28} +{c['added']} / -{c['removed']} lines")
    lines.append("")
    for c in sorted(changes, key=lambda r: r["hostname"]):
        lines.append("─" * 60)
        lines.append(f"{c['hostname']}   ({c['prev']} → {c['curr']})")
        lines.append("─" * 60)
        body = c["diff"].splitlines()
        if len(body) > max_lines_per_device:
            body = body[:max_lines_per_device]
            body.append(f"... (diff truncated at {max_lines_per_device} lines; "
                        f"full diff in the web UI)")
        lines.extend(body)
        lines.append("")
    return "\n".join(lines)
