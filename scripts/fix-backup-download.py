#!/usr/bin/env python3
"""
One-shot patch: make the dashboard list encrypted backups (.cfg.enc) and
decrypt them on download so operators get readable running-config.

Safe to run on a live server:
  * Backs up app.py before editing.
  * Refuses to modify anything unless the exact original code is present.
  * Idempotent — running twice is a no-op after the first success.

Usage:
  sudo python3 fix-backup-download.py [/path/to/aruba_agent/web/app.py]

If no path is given it defaults to /opt/aruba-agent/aruba_agent/web/app.py.
"""
import os
import sys
import time

DEFAULT = "/opt/aruba-agent/aruba_agent/web/app.py"
path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT

if not os.path.isfile(path):
    sys.exit(f"ERROR: {path} not found. Pass the correct path as an argument.")

src = open(path).read()

# ── Edit 1: list filter ──────────────────────────────────────────────────────
old_list = '''        files = sorted(
            [f for f in os.listdir(host_dir) if f.endswith(".cfg")],
            reverse=True,
        )'''
new_list = '''        files = sorted(
            [f for f in os.listdir(host_dir)
             if f.endswith(".cfg") or f.endswith(".cfg.enc")],
            reverse=True,
        )'''

# ── Edit 2: decrypt on download ──────────────────────────────────────────────
old_dl = '''        """Stream a backup .cfg file as a download."""
        if not all(c.isalnum() or c in "-_." for c in hostname):
            abort(400)
        if not all(c.isalnum() or c in "-_." for c in filename):
            abort(400)
        filepath = os.path.join(backup_path, hostname, filename)
        real_backup = os.path.realpath(backup_path)
        real_file   = os.path.realpath(filepath)
        if not real_file.startswith(real_backup + os.sep):
            abort(403)
        if not os.path.isfile(real_file):
            abort(404)
        return send_file(real_file, as_attachment=True, download_name=filename)'''
new_dl = '''        """Stream a backup config as a download.

        Backups are encrypted at rest (``.cfg.enc``). We decrypt in-memory
        with the agent master key so the operator downloads readable
        running-config — the plaintext never lands on disk. Legacy
        cleartext ``.cfg`` files pass through unchanged.
        """
        import io
        from aruba_agent.tasks.backup import decrypt_backup

        if not all(c.isalnum() or c in "-_." for c in hostname):
            abort(400)
        if not all(c.isalnum() or c in "-_." for c in filename):
            abort(400)
        filepath = os.path.join(backup_path, hostname, filename)
        real_backup = os.path.realpath(backup_path)
        real_file   = os.path.realpath(filepath)
        if not real_file.startswith(real_backup + os.sep):
            abort(403)
        if not os.path.isfile(real_file):
            abort(404)

        try:
            plaintext = decrypt_backup(real_file)
        except Exception as exc:
            log.error("Backup decrypt failed for %s: %s", real_file, exc)
            abort(500)

        # Hand the browser a .cfg name even for .cfg.enc sources.
        download_name = filename[:-4] if filename.endswith(".enc") else filename
        return send_file(
            io.BytesIO(plaintext),
            as_attachment=True,
            download_name=download_name,
            mimetype="text/plain",
        )'''

# The two edits are handled independently. Different builds format the
# list filter on one or two lines and may already include ".cfg.enc",
# so we only insist on the download edit, which is the one that matters.
if "decrypt_backup(real_file)" in src:
    print("Already patched — download route decrypts. Nothing to do.")
    sys.exit(0)

# ── List filter: fix only if it's the .cfg-only variant (one or two lines) ────
list_variants = {
    old_list: new_list,
    # Single-line form seen on some builds:
    '[f for f in os.listdir(host_dir) if f.endswith(".cfg")]':
        '[f for f in os.listdir(host_dir) if f.endswith(".cfg") or f.endswith(".cfg.enc")]',
}
list_status = "already includes .cfg.enc — left as is"
for _old, _new in list_variants.items():
    if _old in src:
        src = src.replace(_old, _new)
        list_status = "patched"
        break

# ── Download route: this is the required edit ─────────────────────────────────
if old_dl not in src:
    print("ERROR: could not find the backup-download block to patch.")
    print("Your app.py may be a different version. No changes made.")
    print("Send the output of:  sudo sed -n '/def api_backup_download/,/return app/p' " + path)
    sys.exit(1)

backup = f"{path}.bak.{time.strftime('%Y%m%d-%H%M%S')}"
with open(backup, "w") as f:
    f.write(src)

src = src.replace(old_dl, new_dl)
with open(path, "w") as f:
    f.write(src)

print(f"List filter: {list_status}")
print("Download route: patched to decrypt .cfg.enc")

# Syntax check the result.
import py_compile
try:
    py_compile.compile(path, doraise=True)
except py_compile.PyCompileError as exc:
    # Roll back on any syntax error.
    with open(path, "w") as f:
        f.write(open(backup).read())
    sys.exit(f"ERROR: patched file failed to compile, rolled back.\n{exc}")

print(f"Patched: {path}")
print(f"Backup:  {backup}")
print("Now restart the service:  sudo systemctl restart aruba-agent")
