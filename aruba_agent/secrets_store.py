"""
Encrypted-at-rest secret storage for the agent.

Why this exists
---------------
Up through v3.0.0 every secret the agent needed — SMTP password, RADIUS
shared secret, switch credentials, SNMPv3 auth/priv passwords — was
written to config.ini in cleartext. A misconfigured backup, a casual
``cat /etc/aruba-agent/config.ini``, or a forgotten support tarball
would spill production credentials. v3.0.1 introduces this module:

* A single Fernet (AES-128-CBC + HMAC-SHA256) master key lives at
  /etc/aruba-agent/master.key with mode 0600 root:root. The systemd
  unit's User= owns it.
* Every sensitive config value is rewritten to its ciphertext form
  ``enc:<urlsafe-b64-token>`` so the agent can tell encrypted values
  from cleartext on sight.
* Reading a value goes through ``decrypt()``. A cleartext value is
  returned unchanged — that's how the auto-migration path bootstraps
  an existing v3.0.0 deployment without locking the operator out.
* Writing a value goes through ``encrypt()``. The caller then stores
  the resulting ``enc:...`` string back to config.ini.

Migration
---------
On first start, ``migrate_config()`` walks every known-sensitive field
in config.ini. Any value that still looks like cleartext is encrypted
in-place and the file is rewritten atomically with a one-time
``.bak`` copy kept beside it. From the next start onward every
sensitive field is already encrypted and the migration is a no-op.

Threading
---------
The SecretManager is constructed once at startup and is effectively
immutable from then on (the master key never changes at runtime).
All methods are safe to call from any thread.

Security caveats
----------------
* This is rest-encryption, not a secrets vault. Anything that can
  read both config.ini AND master.key on disk can recover the
  cleartext. The point is to defeat casual exposure (tarballs,
  backups, accidental ``cat``s) — not a determined local attacker.
* Run only on a host where the systemd unit User= can't be elevated
  to. The aruba-agent service account should own master.key and have
  no shell.
* Rotation: not supported in v3.0.1. To rotate, decrypt config.ini
  with the old key, replace master.key, re-run migration.
"""

from __future__ import annotations

import configparser
import io
import logging
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


log = logging.getLogger(__name__)


# Marker that tells encrypted-at-rest values apart from cleartext.
# Kept short so config.ini stays human-readable; "enc:" is unlikely
# to collide with any real password (passwords with literal colons
# DO exist, but no real password begins with "enc:" exactly).
_PREFIX = "enc:"


# Default location for the Fernet master key. Overridable via
# [agent] master_key_file = ... in config.ini.
DEFAULT_MASTER_KEY_PATH = "/etc/aruba-agent/master.key"


# Sensitive fields by config section. Auto-migration walks this list
# and encrypts every value it finds in cleartext.
#
# Section names ending in ".*" are prefixes — they match every section
# whose name starts with that prefix (so all [snmp.<name>] subsections
# get covered without enumerating each one).
SENSITIVE_FIELDS: List[Tuple[str, Tuple[str, ...]]] = [
    ("credentials",          ("password",)),
    ("credentials.cisco",    ("password", "enable_secret")),
    ("credentials.arista",   ("password", "enable_password")),
    ("smtp",                 ("password",)),
    ("radius",               ("secret",)),
    ("web",                  ("secret_key",)),
    ("snmp",                 ("auth_password", "priv_password")),
    ("snmp.*",               ("auth_password", "priv_password")),
]


# ─── module-level singleton ──────────────────────────────────────────────────
# The SecretManager is shared by every component that needs to read a
# password from config (notifier, drivers, tasks, web routes). Wiring
# it through every constructor would touch a lot of code; a module-
# level singleton keeps the diff small and is fine here because the
# manager is immutable after install().

_INSTANCE: "Optional[SecretManager]" = None


def install(manager: "SecretManager") -> None:
    """Register the process-wide SecretManager. Called once from main()."""
    global _INSTANCE
    _INSTANCE = manager


def get() -> "Optional[SecretManager]":
    """Return the registered SecretManager, or None if not installed."""
    return _INSTANCE


def decrypt(value: str) -> str:
    """
    Decrypt ``value`` if it carries the ``enc:`` prefix; otherwise
    return it unchanged. Safe to call before ``install()`` — a missing
    SecretManager just means we couldn't possibly have valid ciphertext
    so the value must already be cleartext.

    This is the canonical hook every config-reading call site should
    use. It's a no-op on cleartext, which preserves backward
    compatibility with v3.0.0 deployments that haven't migrated yet.
    """
    if not value or not isinstance(value, str):
        return value
    if not value.startswith(_PREFIX):
        return value
    sm = _INSTANCE
    if sm is None:
        # We can see an encrypted value but have no key to decrypt it.
        # Returning the ciphertext would be worse than returning empty
        # (callers would pass "enc:..." as a password and login would
        # fail with a confusing error). Log once and return empty so
        # the caller's "missing credential" path runs cleanly.
        log.error(
            "Encountered an enc:... value but no SecretManager is "
            "installed. Returning empty string — check master.key path."
        )
        return ""
    return sm.decrypt(value)


def is_encrypted(value: str) -> bool:
    """True if ``value`` is in the on-disk encrypted form."""
    return bool(value) and isinstance(value, str) and value.startswith(_PREFIX)


# ─── SecretManager ────────────────────────────────────────────────────────────

class SecretManager:
    """
    Wraps a Fernet master key. Constructed once at startup; pass the
    path to ``master.key`` and the constructor will load it (creating
    one if needed).
    """

    def __init__(self, key_path: str, *, create_if_missing: bool = True) -> None:
        # Lazy import so the agent still imports cleanly on a host
        # that's missing 'cryptography' (e.g. during partial install).
        # We fail loud only when someone actually calls encrypt/decrypt.
        from cryptography.fernet import Fernet, InvalidToken
        self._Fernet      = Fernet
        self._InvalidToken = InvalidToken

        self._key_path = Path(key_path)
        self._fernet   = self._load_or_create(create_if_missing)

    # ─── key bootstrap ────────────────────────────────────────────────────────

    def _load_or_create(self, create_if_missing: bool):
        """
        Load the master key from disk. If it's missing and
        ``create_if_missing`` is True, generate a fresh 32-byte Fernet
        key and persist it with mode 0600.
        """
        path = self._key_path
        if path.exists():
            try:
                with path.open("rb") as f:
                    key = f.read().strip()
                fernet = self._Fernet(key)
                log.info("Master key loaded from %s", path)
                return fernet
            except Exception as exc:
                # Don't silently regenerate — that would orphan every
                # previously-encrypted value in config.ini.
                raise RuntimeError(
                    f"Master key at {path} is unreadable or malformed: "
                    f"{exc}. Restore from backup or delete the file "
                    f"AND re-enter all passwords."
                ) from exc

        if not create_if_missing:
            raise FileNotFoundError(f"Master key not found at {path}")

        log.warning(
            "No master key at %s — generating a new one. All passwords "
            "will be encrypted with this key. Back it up; if you lose "
            "this file you lose every encrypted password.", path,
        )
        new_key = self._Fernet.generate_key()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Write via tempfile + os.replace for atomicity; chmod 0600
            # before the rename so the file is never world-readable.
            fd, tmp_name = tempfile.mkstemp(
                prefix=".master-", suffix=".tmp", dir=str(path.parent),
            )
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(new_key)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_name, path)
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
            except Exception:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
        except OSError as exc:
            raise RuntimeError(
                f"Could not create master key at {path}: {exc}. "
                f"The agent user needs write access to {path.parent}."
            ) from exc

        return self._Fernet(new_key)

    # ─── encrypt / decrypt ────────────────────────────────────────────────────

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt ``plaintext`` and return the on-disk form
        ``enc:<token>``. Empty strings are returned as-is — we don't
        encrypt blanks (it produces noise in config.ini for fields the
        operator deliberately left empty).
        """
        if not plaintext:
            return ""
        if is_encrypted(plaintext):
            # Idempotent: re-encrypting an already-encrypted value is
            # a no-op. Useful for the migration loop which may run on
            # a partially-migrated config.
            return plaintext
        token = self._fernet.encrypt(plaintext.encode("utf-8"))
        return _PREFIX + token.decode("ascii")

    def decrypt(self, value: str) -> str:
        """
        Decrypt an ``enc:<token>`` value. Cleartext values pass
        through unchanged so callers can use this on any config field
        without checking the prefix first.
        """
        if not value or not value.startswith(_PREFIX):
            return value
        token = value[len(_PREFIX):].encode("ascii")
        try:
            return self._fernet.decrypt(token).decode("utf-8")
        except self._InvalidToken:
            log.error(
                "Could not decrypt a stored secret — the master key may "
                "have been rotated without re-encrypting config.ini, or "
                "the ciphertext is corrupt. Returning empty string."
            )
            return ""


# ─── config migration ─────────────────────────────────────────────────────────

def _fields_for_section(section_name: str) -> Tuple[str, ...]:
    """
    Return the sensitive field tuple for ``section_name``. Exact-match
    sections win over prefix matches (so [snmp] with its own field set
    takes precedence over [snmp.*]).
    """
    # Exact match first
    for sec, fields in SENSITIVE_FIELDS:
        if sec == section_name:
            return fields
    # Prefix match (".*")
    for sec, fields in SENSITIVE_FIELDS:
        if sec.endswith(".*"):
            prefix = sec[:-2] + "."        # "snmp.*" → "snmp."
            if section_name.startswith(prefix):
                return fields
    return ()


def migrate_config(
    config_path: str,
    manager: SecretManager,
    *,
    backup_suffix: str = ".bak",
) -> List[Tuple[str, str]]:
    """
    Walk ``config_path`` and encrypt every sensitive field that's still
    in cleartext. Returns a list of ``(section, key)`` tuples for the
    fields that were rewritten — empty list if nothing needed doing.

    Behaviour:
      * Reads the file fresh; never trusts an in-memory parser.
      * Preserves the header comment block (everything before the
        first [section]).
      * Writes a one-time ``<path>.bak`` the first time it rewrites,
        so the operator has a recovery path if anything goes wrong.
        Subsequent runs don't overwrite the .bak.
      * Atomic write via tempfile + os.replace.

    Empty values are skipped — encrypting "" produces noise and the
    runtime falls through to a default anyway.
    """
    path = Path(config_path)
    if not path.exists():
        log.info("Migrate: %s does not exist — nothing to encrypt", path)
        return []

    # Read header verbatim so we don't lose the file's identifying
    # comment block. configparser.write() can't round-trip leading
    # comments, so we capture them manually before parsing.
    header_lines = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            stripped = line.lstrip()
            if stripped.startswith("[") and "]" in stripped:
                break
            header_lines.append(line)
    header = "".join(header_lines)

    cfg = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    cfg.read(path, encoding="utf-8")

    changed: List[Tuple[str, str]] = []
    for section in cfg.sections():
        fields = _fields_for_section(section)
        if not fields:
            continue
        for key in fields:
            if not cfg.has_option(section, key):
                continue
            value = cfg.get(section, key, raw=True)
            if not value or is_encrypted(value):
                continue
            cfg.set(section, key, manager.encrypt(value))
            changed.append((section, key))

    if not changed:
        log.info("Migrate: every sensitive field already encrypted — nothing to do")
        return []

    # Keep a one-time .bak so the operator can recover if the migration
    # somehow corrupts a value. We only write the .bak if one doesn't
    # already exist, otherwise we'd clobber the original on every run.
    bak_path = path.with_suffix(path.suffix + backup_suffix)
    if not bak_path.exists():
        try:
            shutil.copy2(path, bak_path)
            try:
                # Match permissions — the .bak holds the same secrets.
                os.chmod(bak_path, stat.S_IMODE(os.stat(path).st_mode))
            except OSError:
                pass
            log.info("Migrate: wrote one-time backup of %s to %s", path, bak_path)
        except OSError as exc:
            log.warning("Migrate: could not write backup %s (%s) — "
                        "continuing anyway", bak_path, exc)

    # Render to string, prepend the header, write atomically.
    buf = io.StringIO()
    cfg.write(buf, space_around_delimiters=True)
    text = header + buf.getvalue()

    try:
        existing_mode = stat.S_IMODE(os.stat(path).st_mode)
    except FileNotFoundError:
        existing_mode = 0o640

    fd, tmp_name = tempfile.mkstemp(
        prefix=".config-", suffix=".tmp", dir=str(path.parent),
    )
    try:
        os.fchmod(fd, existing_mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
        try:
            os.chmod(path, existing_mode)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise

    log.info(
        "Migrate: encrypted %d field(s) in %s: %s",
        len(changed), path,
        ", ".join(f"[{s}] {k}" for s, k in changed),
    )
    return changed


# ─── convenience helpers ─────────────────────────────────────────────────────

def cfg_get(cfg, section: str, key: str, fallback: str = "") -> str:
    """
    Read ``cfg[section][key]`` and decrypt it if needed. A drop-in
    replacement for ``cfg.get(section, key, fallback=...)`` whenever
    the field might be encrypted.

    This is what every call site that reads a password should use.
    """
    try:
        raw = cfg.get(section, key, fallback=fallback)
    except (configparser.NoSectionError, configparser.NoOptionError):
        return fallback
    return decrypt(raw or "")


def section_get(section, key: str, fallback: str = "") -> str:
    """
    Like ``cfg_get`` but takes a SectionProxy directly. Convenience
    for code paths that already have ``cfg[section]`` in hand
    (notifier, drivers, etc.).
    """
    raw = section.get(key, fallback)
    return decrypt(raw or "")
