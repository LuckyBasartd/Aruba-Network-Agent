"""
In-app Help content, encrypted at rest.

The Help page (/help) serves the operator troubleshooting guide to logged-in
users only. Per the app's security model, the served copy is kept
Fernet-encrypted on disk (``help.md.enc`` in the runtime data dir) and
decrypted **in memory** on each request — the same treatment config backups
get. The plaintext source (``aruba_agent/web/help_content.md``) ships with the
code as the editable template; this module keeps the encrypted copy in sync
from it.

Everything is best-effort: if there's no SecretManager (no master key) or the
data dir isn't writable, we fall back to serving the plaintext source so Help
still works — it just isn't stored encrypted in that degraded case.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from aruba_agent import secrets_store

log = logging.getLogger(__name__)


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def ensure_encrypted(enc_path: str, source_path: str) -> bool:
    """Write/refresh the encrypted-at-rest copy from *source_path* when it's
    missing or stale. Returns True if an encrypted copy exists afterwards."""
    sm = secrets_store.get()
    if sm is None or not os.path.exists(source_path):
        return os.path.exists(enc_path)
    try:
        stale = (not os.path.exists(enc_path) or
                 os.path.getmtime(source_path) > os.path.getmtime(enc_path))
        if stale:
            token = sm.encrypt(_read(source_path))     # -> "enc:<fernet>"
            tmp = enc_path + ".tmp"
            with open(tmp, "w", encoding="ascii") as fh:
                fh.write(token)
            os.replace(tmp, enc_path)
            log.info("help: refreshed encrypted copy at %s", enc_path)
        return True
    except OSError as exc:
        log.warning("help: could not write encrypted copy %s: %s", enc_path, exc)
        return os.path.exists(enc_path)


def load_markdown(enc_path: str, source_path: str) -> str:
    """Return the Help markdown, preferring the encrypted-at-rest copy
    (decrypted in memory). Falls back to the plaintext source, then to a
    stub so the page never hard-fails."""
    ensure_encrypted(enc_path, source_path)
    sm = secrets_store.get()
    if sm is not None and os.path.exists(enc_path):
        try:
            text = sm.decrypt(_read(enc_path).strip())
            if text:
                return text
        except OSError as exc:
            log.warning("help: could not read %s: %s", enc_path, exc)
    if os.path.exists(source_path):
        try:
            return _read(source_path)
        except OSError:
            pass
    return "# Help\n\nHelp content is unavailable on this install."


def encrypt_help_cli(source_path: str, enc_path: str) -> int:
    """CLI helper: (re)generate the encrypted copy. Returns process exit code."""
    sm = secrets_store.get()
    if sm is None:
        print("--encrypt-help: no SecretManager / master key available", flush=True)
        return 2
    if not os.path.exists(source_path):
        print(f"--encrypt-help: source not found: {source_path}", flush=True)
        return 2
    try:
        token = sm.encrypt(_read(source_path))
        tmp = enc_path + ".tmp"
        with open(tmp, "w", encoding="ascii") as fh:
            fh.write(token)
        os.replace(tmp, enc_path)
    except OSError as exc:
        print(f"--encrypt-help: write failed: {exc}", flush=True)
        return 2
    print(f"--encrypt-help: wrote {enc_path} ({os.path.getsize(enc_path)} bytes)", flush=True)
    return 0
