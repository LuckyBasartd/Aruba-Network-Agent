#!/usr/bin/env python3
"""
One-shot state-snapshot scrubber.

The credential leak fixed in v3.0.2's "redact at every exception-capture
site" pass only prevents NEW leaks from being written. If an operator
upgraded mid-flap, the existing state.json's ``backup.failed_devices``
list may still contain entries with cleartext credentials in their
``issue`` field — which the dashboard keeps rendering until the next
backup run overwrites the list.

Run this script ONCE after deploying v3.0.2 to scrub any existing
leaks from /var/lib/aruba-agent/state.json. Idempotent: a second run
is a no-op.

Usage:
    sudo -u aruba-agent /opt/aruba-agent/venv/bin/python \\
        /opt/aruba-agent/scripts/scrub-state-leaks.py \\
        [/var/lib/aruba-agent/state.json]

Exits 0 on a clean (or successfully scrubbed) file, 1 on read/write
error, 2 if the JSON was unreadable.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

# Use the same redactor the runtime now uses, so what the operator
# sees in the dashboard after this scrub matches what they'd see for
# any future error.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
from aruba_agent.secrets_store import redact


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "/var/lib/aruba-agent/state.json"
    if not os.path.exists(path):
        print(f"state file not found: {path}", file=sys.stderr)
        return 1

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"could not read {path}: {exc}", file=sys.stderr)
        return 2

    failed = (data.get("backup") or {}).get("failed_devices") or []
    rewrites = 0
    for entry in failed:
        issue = entry.get("issue") or ""
        clean = redact(issue)
        if clean != issue:
            entry["issue"] = clean
            rewrites += 1

    if rewrites == 0:
        print("No leaked credentials found in state.json — nothing to do.")
        return 0

    # Atomic write — match the agent's own _save() pattern.
    fd, tmp = tempfile.mkstemp(
        prefix=".state-scrub-", suffix=".tmp",
        dir=os.path.dirname(path),
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(data, out, indent=2, sort_keys=True)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    except Exception as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        print(f"could not write {path}: {exc}", file=sys.stderr)
        return 1

    print(f"Scrubbed {rewrites} entry/entries in {path}.")
    print("Reload the dashboard — leaked credentials are gone from the FAILED panel.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
