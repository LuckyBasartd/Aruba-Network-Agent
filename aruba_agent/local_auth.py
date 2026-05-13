"""
Local user credential store.

Why this exists
---------------
RADIUS is the primary auth path, but the operator needs SOMETHING that
works on a clean install before RADIUS is even configured — and a
recovery path back into the dashboard if RADIUS goes down. This module
provides that:

* scrypt-hashed passwords (no plaintext on disk, no extra dependencies)
* a JSON store at /var/lib/aruba-agent/users.json (mode 0600)
* a built-in default of admin / admin on first start, flagged
  must_change=true so the operator is forced to set a real password
  on first login
* atomic writes so a crash mid-save can't corrupt the file

Threading
---------
All public methods take an internal lock; safe to call from any thread.

Security caveats
----------------
* scrypt with the parameters below (N=2**14, r=8, p=1) takes ~80ms on
  modest hardware — fast enough for interactive login, slow enough to
  make offline brute-force on a leaked file painful.
* The store sits beside the agent state on disk. If an attacker can
  read /var/lib/aruba-agent/users.json they can also read state.json
  and likely the config — local-auth doesn't pretend to be a vault.
* No rate limiting at this layer. The web layer owns that.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


log = logging.getLogger(__name__)


# scrypt parameters — Mozilla's "interactive" tier. dklen=64 gives a
# 512-bit derived key. SALT_BYTES gives a 128-bit salt.
_SCRYPT_N    = 2 ** 14
_SCRYPT_R    = 8
_SCRYPT_P    = 1
_SCRYPT_DKLEN = 64
_SALT_BYTES   = 16

DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin"


# ─── helpers ───────────────────────────────────────────────────────────────────

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def hash_password(password: str) -> str:
    """
    Produce a self-describing scrypt hash string:
        scrypt$N=<n>$r=<r>$p=<p>$<b64salt>$<b64hash>
    """
    salt   = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt   = salt,
        n      = _SCRYPT_N,
        r      = _SCRYPT_R,
        p      = _SCRYPT_P,
        dklen  = _SCRYPT_DKLEN,
    )
    return f"scrypt$N={_SCRYPT_N}$r={_SCRYPT_R}$p={_SCRYPT_P}${_b64e(salt)}${_b64e(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    """
    Constant-time verification against an encoded hash. Tolerant of
    parameter changes — the parameters are read from the encoded string,
    not pinned to the constants above (so future increases to N/r/p
    don't break old hashes).
    """
    try:
        scheme, n_part, r_part, p_part, b64salt, b64hash = encoded.split("$")
        if scheme != "scrypt":
            return False
        n = int(n_part.split("=", 1)[1])
        r = int(r_part.split("=", 1)[1])
        p = int(p_part.split("=", 1)[1])
        salt   = _b64d(b64salt)
        target = _b64d(b64hash)
    except (ValueError, IndexError):
        return False

    try:
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt   = salt,
            n      = n,
            r      = r,
            p      = p,
            dklen  = len(target),
        )
    except Exception:
        return False
    return secrets.compare_digest(digest, target)


# ─── store ────────────────────────────────────────────────────────────────────

class LocalAuthStore:
    """
    JSON-backed user store. Loads on construction, writes atomically.

    File schema:
        {
          "users": [
            {
              "username":      "admin",
              "password_hash": "scrypt$...",
              "must_change":   true,
              "created":       "2026-04-27T12:00:00",
              "last_login":    null
            }, ...
          ]
        }
    """

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._lock = threading.RLock()
        self._users: Dict[str, dict] = {}
        self._load()

    # ─── persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._path.exists():
            log.info("Local auth: no user store at %s — will bootstrap", self._path)
            return
        try:
            with self._path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            for u in data.get("users", []):
                name = u.get("username")
                if name and u.get("password_hash"):
                    self._users[name] = u
            log.info("Local auth: loaded %d user(s) from %s",
                     len(self._users), self._path)
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Local auth: could not read %s (%s) — starting empty",
                        self._path, exc)

    def _save(self) -> None:
        """
        Atomic save: temp file + os.replace, mode 0600.
        Caller already holds self._lock.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=".users-", suffix=".tmp", dir=str(self._path.parent),
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                json.dump(
                    {"users": list(self._users.values())},
                    tmp, indent=2, sort_keys=True,
                )
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_name, self._path)
            # Replace doesn't always carry mode forward on every FS — re-set.
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    # ─── bootstrap ────────────────────────────────────────────────────────────

    def bootstrap_default_admin(self) -> bool:
        """
        Ensure at least one user exists. If the store is empty, create
        the default admin / admin entry with must_change=true. Returns
        True if a default was created, False if users were already present.
        """
        with self._lock:
            if self._users:
                return False
            log.warning(
                "Local auth: no users found — creating default %s/%s "
                "(must change on first login)",
                DEFAULT_USERNAME, DEFAULT_PASSWORD,
            )
            self._users[DEFAULT_USERNAME] = {
                "username":      DEFAULT_USERNAME,
                "password_hash": hash_password(DEFAULT_PASSWORD),
                "must_change":   True,
                "created":       datetime.now().isoformat(timespec="seconds"),
                "last_login":    None,
            }
            self._save()
            return True

    # ─── authentication ──────────────────────────────────────────────────────

    def authenticate(self, username: str, password: str) -> bool:
        """
        Constant-time username + password check. Records a last_login
        timestamp on success. Returns False for empty inputs, unknown
        users, or mismatching password.
        """
        if not username or not password:
            return False
        with self._lock:
            user = self._users.get(username)
            if not user:
                # Run a dummy verify to keep timing consistent
                # (don't leak whether the username exists).
                verify_password(password,
                                "scrypt$N=16384$r=8$p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAA")
                return False
            if not verify_password(password, user["password_hash"]):
                return False
            user["last_login"] = datetime.now().isoformat(timespec="seconds")
            self._save()
            return True

    def must_change_password(self, username: str) -> bool:
        with self._lock:
            user = self._users.get(username)
            return bool(user and user.get("must_change"))

    # Minimum password length enforced at the store layer. The web form
    # enforces the same policy; defense in depth so a future API caller
    # can't bypass it.
    MIN_PASSWORD_LEN = 8

    def change_password(self, username: str, new_password: str) -> bool:
        """
        Update the password for an existing user and clear the
        must_change flag. Returns True on success.
        """
        if not new_password or len(new_password) < self.MIN_PASSWORD_LEN:
            return False
        with self._lock:
            user = self._users.get(username)
            if not user:
                return False
            user["password_hash"] = hash_password(new_password)
            user["must_change"]   = False
            self._save()
            log.info("Local auth: password changed for user=%s", username)
            return True

    # ─── TOTP 2FA (T3.3) ─────────────────────────────────────────────────────

    def totp_enabled(self, username: str) -> bool:
        """True if the user has enrolled in TOTP 2FA."""
        with self._lock:
            user = self._users.get(username)
            return bool(user and user.get("totp_secret"))

    def get_totp_secret(self, username: str) -> Optional[str]:
        """Return the user's TOTP secret (base32) or None if not enrolled."""
        with self._lock:
            user = self._users.get(username)
            return user.get("totp_secret") if user else None

    def enroll_totp(self, username: str, secret: str,
                    recovery_hashes: List[str]) -> bool:
        """
        Persist a TOTP secret + scrypt-hashed recovery codes. Caller
        (the web layer) is responsible for generating both — keeping
        TOTP / qrcode imports out of this module so a host without
        pyotp installed still loads the agent.
        """
        if not secret or not recovery_hashes:
            return False
        with self._lock:
            user = self._users.get(username)
            if not user:
                return False
            user["totp_secret"]     = secret
            user["totp_recovery"]   = list(recovery_hashes)
            user["totp_enrolled"]   = datetime.now().isoformat(timespec="seconds")
            self._save()
            log.info("Local auth: TOTP enrolled for user=%s", username)
            return True

    def disable_totp(self, username: str) -> bool:
        """Strip every TOTP field from the user. Used by Disable 2FA."""
        with self._lock:
            user = self._users.get(username)
            if not user:
                return False
            changed = False
            for k in ("totp_secret", "totp_recovery", "totp_enrolled"):
                if k in user:
                    del user[k]
                    changed = True
            if changed:
                self._save()
                log.info("Local auth: TOTP disabled for user=%s", username)
            return changed

    def consume_recovery_code(self, username: str, candidate: str) -> bool:
        """
        Check ``candidate`` against the user's stored recovery hashes;
        on a match, remove that hash so the code can't be reused.
        Returns True on success.
        """
        if not candidate:
            return False
        # Recovery codes are case-insensitive + dash-tolerant ('AB1C-DE2F').
        normalized = candidate.replace("-", "").replace(" ", "").upper()
        with self._lock:
            user = self._users.get(username)
            if not user:
                return False
            for stored in list(user.get("totp_recovery", [])):
                if verify_password(normalized, stored):
                    user["totp_recovery"].remove(stored)
                    self._save()
                    log.info("Local auth: TOTP recovery code consumed for user=%s "
                             "(remaining=%d)",
                             username, len(user["totp_recovery"]))
                    return True
            return False

    def recovery_codes_remaining(self, username: str) -> int:
        with self._lock:
            user = self._users.get(username)
            if not user:
                return 0
            return len(user.get("totp_recovery", []))

    # ─── WebAuthn passkeys (F2b) ─────────────────────────────────────────────
    #
    # Per-user passkey list. Each entry is:
    #   {
    #     "credential_id":  "<base64url>",
    #     "public_key":     "<base64url COSE key>",
    #     "sign_count":     int,         # cloning detection
    #     "name":           "iPhone",    # operator label
    #     "created":        "ISO ts",
    #     "last_used":      "ISO ts"     # null until first use
    #   }
    #
    # We delegate all WebAuthn cryptography to aruba_agent.passkeys —
    # this module just owns persistence.

    def add_passkey(self, username: str, passkey: dict) -> bool:
        with self._lock:
            user = self._users.get(username)
            if not user:
                return False
            user.setdefault("passkeys", []).append(passkey)
            self._save()
            log.info("Local auth: passkey enrolled for user=%s (name=%s)",
                     username, passkey.get("name"))
            return True

    def list_passkeys(self, username: str) -> List[dict]:
        with self._lock:
            user = self._users.get(username)
            if not user:
                return []
            return [
                {
                    "credential_id": p.get("credential_id", ""),
                    "name":          p.get("name", ""),
                    "created":       p.get("created"),
                    "last_used":     p.get("last_used"),
                    "sign_count":    p.get("sign_count", 0),
                }
                for p in user.get("passkeys", [])
            ]

    def get_passkey(self, username: str, credential_id: str) -> Optional[dict]:
        """Return the full passkey dict (incl. public_key + sign_count)
        for verification, or None."""
        with self._lock:
            user = self._users.get(username)
            if not user:
                return None
            for p in user.get("passkeys", []):
                if p.get("credential_id") == credential_id:
                    return dict(p)
        return None

    def update_passkey_after_use(
        self, username: str, credential_id: str, new_sign_count: int,
    ) -> bool:
        """Persist a successful authentication. Mandatory per the
        WebAuthn spec — the sign_count detects cloned authenticators."""
        with self._lock:
            user = self._users.get(username)
            if not user:
                return False
            for p in user.get("passkeys", []):
                if p.get("credential_id") == credential_id:
                    p["sign_count"] = new_sign_count
                    p["last_used"]  = datetime.now().isoformat(timespec="seconds")
                    self._save()
                    return True
        return False

    def remove_passkey(self, username: str, credential_id: str) -> bool:
        with self._lock:
            user = self._users.get(username)
            if not user:
                return False
            keys = user.get("passkeys", [])
            new = [p for p in keys if p.get("credential_id") != credential_id]
            if len(new) == len(keys):
                return False
            user["passkeys"] = new
            self._save()
            log.info("Local auth: passkey removed for user=%s (%s)",
                     username, credential_id[:12])
            return True

    def list_credential_ids(self, username: str) -> List[str]:
        """Lightweight lookup for the WebAuthn assertion options
        ('which credentials does this user have'). Pre-login path
        so it tolerates an unknown username silently."""
        with self._lock:
            user = self._users.get(username)
            if not user:
                return []
            return [p.get("credential_id", "")
                    for p in user.get("passkeys", [])
                    if p.get("credential_id")]

    def find_user_by_credential_id(self, credential_id: str) -> Optional[str]:
        """Reverse lookup for username-less passkey login. Returns the
        username that owns this credential, or None."""
        with self._lock:
            for username, user in self._users.items():
                for p in user.get("passkeys", []):
                    if p.get("credential_id") == credential_id:
                        return username
        return None

    # ─── user management ─────────────────────────────────────────────────────

    def list_users(self) -> List[dict]:
        """
        Return a list of {username, must_change, created, last_login}
        dicts — never the password hash.
        """
        with self._lock:
            return [
                {
                    "username":    u["username"],
                    "must_change": bool(u.get("must_change")),
                    "created":     u.get("created"),
                    "last_login":  u.get("last_login"),
                }
                for u in self._users.values()
            ]

    def add_user(
        self,
        username: str,
        password: str,
        must_change: bool = False,
    ) -> bool:
        """Create a new user. Returns False if the username is taken."""
        if not username or not password:
            return False
        with self._lock:
            if username in self._users:
                return False
            self._users[username] = {
                "username":      username,
                "password_hash": hash_password(password),
                "must_change":   must_change,
                "created":       datetime.now().isoformat(timespec="seconds"),
                "last_login":    None,
            }
            self._save()
            log.info("Local auth: user added: %s", username)
            return True

    def remove_user(self, username: str) -> bool:
        """Remove a user. Refuses to remove the last user."""
        with self._lock:
            if username not in self._users:
                return False
            if len(self._users) <= 1:
                log.warning("Local auth: refusing to remove last user (%s)", username)
                return False
            del self._users[username]
            self._save()
            log.info("Local auth: user removed: %s", username)
            return True
