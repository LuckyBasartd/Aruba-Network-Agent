"""
API token store — scrypt-hashed tokens with explicit scopes.

Why this exists
---------------
Up through v3.0.3 the only way to script the agent was to drive the
browser-session flow: log in as a user, scrape the session cookie,
include it on subsequent calls. That works but it leaks operator
credentials into automation, can't be revoked without changing the
operator's password, and pollutes the audit log with the operator's
identity instead of the bot's.

This module gives operators a way to mint long-lived, opaque tokens
with limited scopes that the web layer accepts as an alternative to
session auth.

Storage
-------
JSON at /var/lib/aruba-agent/api_tokens.json (mode 600, agent-owned).
Tokens are stored as scrypt hashes, never cleartext. The cleartext
form is shown exactly once at mint time — Settings UI displays it,
then it lives only with the operator who created it.

Token format
------------
``aat_`` prefix + 48 random base64url characters. ``aat`` =
"aruba agent token". The prefix makes the token instantly
recognisable in logs / git history / paste accidents, which gives
operators a fighting chance to revoke before something bad
propagates.

Scopes
------
Each token carries a list of scope strings. The web layer's
@require_scope decorator checks them. Recognised scopes:

    state.read         — GET /api/state and adjacent read endpoints
    backup.trigger     — POST /api/backup/trigger
    scanner.trigger    — POST /api/scanner/trigger
    arp.trigger        — POST /api/arp/<location>/trigger
    snmp.test          — POST /api/settings/snmp/test
    *                  — wildcard, all current and future scopes

Unrecognised scopes are accepted at mint time (forward-compatible with
new endpoints) but never match a check.

Threading
---------
Same lock model as local_auth: one RLock, all public methods take it.
Safe to call from any Flask worker thread.
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
from typing import Dict, List, Optional, Tuple


log = logging.getLogger(__name__)


_PREFIX        = "aat_"
_TOKEN_BYTES   = 36          # 36 bytes → 48 base64url chars after stripping padding
_SCRYPT_N      = 2 ** 14
_SCRYPT_R      = 8
_SCRYPT_P      = 1
_SCRYPT_DKLEN  = 32
_SALT_BYTES    = 16

# Built-in known scopes. Tokens may carry others (e.g. for future
# endpoints), but only these are recognised by has_scope() today.
KNOWN_SCOPES: Tuple[str, ...] = (
    "state.read",
    "backup.trigger",
    "scanner.trigger",
    "arp.trigger",
    "snmp.test",
)


# ─── helpers ────────────────────────────────────────────────────────────────

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _hash_token(plaintext: str) -> str:
    """Produce a self-describing scrypt hash: scrypt$N=..$r=..$p=..$salt$hash."""
    salt   = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        plaintext.encode("utf-8"),
        salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return f"scrypt$N={_SCRYPT_N}$r={_SCRYPT_R}$p={_SCRYPT_P}${_b64e(salt)}${_b64e(digest)}"


def _verify_token(plaintext: str, encoded: str) -> bool:
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
            plaintext.encode("utf-8"),
            salt=salt, n=n, r=r, p=p, dklen=len(target),
        )
    except Exception:
        return False
    return secrets.compare_digest(digest, target)


# ─── store ──────────────────────────────────────────────────────────────────

class ApiTokenStore:
    """
    JSON-backed token store. Loads on construction, writes atomically.

    File schema:
        {
          "tokens": [
            {
              "id":           "tok_abc123",        # short opaque id
              "name":         "grafana scraper",
              "scopes":       ["state.read"],
              "hash":         "scrypt$...",
              "created":      "2026-05-12T14:30:00",
              "created_by":   "mvieira",
              "last_used":    null
            }, ...
          ]
        }
    """

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._lock = threading.RLock()
        self._tokens: Dict[str, dict] = {}    # keyed by id
        self._load()

    # ─── persistence ─────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._path.exists():
            log.info("API tokens: no store at %s — starting empty", self._path)
            return
        try:
            with self._path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            for t in data.get("tokens", []):
                tid = t.get("id")
                if tid and t.get("hash"):
                    self._tokens[tid] = t
            log.info("API tokens: loaded %d token(s)", len(self._tokens))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("API tokens: could not read %s (%s) — starting empty",
                        self._path, exc)

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=".api-tokens-", suffix=".tmp", dir=str(self._path.parent),
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                json.dump(
                    {"tokens": list(self._tokens.values())},
                    tmp, indent=2, sort_keys=True,
                )
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_name, self._path)
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

    # ─── mint / revoke / list ────────────────────────────────────────────────

    def mint(
        self,
        name: str,
        scopes: List[str],
        created_by: str,
    ) -> Tuple[str, str]:
        """
        Mint a new token. Returns (token_id, cleartext). The cleartext
        is shown to the operator exactly once — the caller is expected
        to display it on the response page and then forget it.
        """
        cleartext = _PREFIX + _b64e(secrets.token_bytes(_TOKEN_BYTES))
        # Short id derived from a separate random; keeps revoke URLs
        # independent of the secret.
        token_id  = "tok_" + _b64e(secrets.token_bytes(6))
        with self._lock:
            self._tokens[token_id] = {
                "id":         token_id,
                "name":       (name or "").strip() or "unnamed",
                "scopes":     list(dict.fromkeys(scopes)),  # dedupe, preserve order
                "hash":       _hash_token(cleartext),
                "created":    datetime.now().isoformat(timespec="seconds"),
                "created_by": created_by or "?",
                "last_used":  None,
            }
            self._save()
        log.info("API token minted: id=%s name=%r scopes=%s by=%s",
                 token_id, name, scopes, created_by)
        return token_id, cleartext

    def revoke(self, token_id: str) -> bool:
        with self._lock:
            if token_id not in self._tokens:
                return False
            del self._tokens[token_id]
            self._save()
        log.info("API token revoked: id=%s", token_id)
        return True

    def list_tokens(self) -> List[dict]:
        """Return token metadata without the hash."""
        with self._lock:
            return [
                {
                    "id":         t["id"],
                    "name":       t.get("name", ""),
                    "scopes":     list(t.get("scopes", [])),
                    "created":    t.get("created"),
                    "created_by": t.get("created_by"),
                    "last_used":  t.get("last_used"),
                }
                for t in self._tokens.values()
            ]

    # ─── authenticate ────────────────────────────────────────────────────────

    def authenticate(self, cleartext: str) -> Optional[dict]:
        """
        Return the token record (without hash) if ``cleartext`` matches
        any stored token, else None. Updates last_used on success.

        Runs in O(N) where N = number of tokens because we don't know
        which entry to check — scrypt is the time floor anyway. Sites
        with > 50 tokens should reconsider their tokens story.
        """
        if not cleartext or not cleartext.startswith(_PREFIX):
            return None
        with self._lock:
            for tid, t in self._tokens.items():
                if _verify_token(cleartext, t["hash"]):
                    t["last_used"] = datetime.now().isoformat(timespec="seconds")
                    self._save()
                    return {
                        "id":     tid,
                        "name":   t.get("name", ""),
                        "scopes": list(t.get("scopes", [])),
                    }
        return None

    @staticmethod
    def has_scope(token_record: dict, required: str) -> bool:
        """True if ``token_record`` carries the required scope (or '*')."""
        scopes = token_record.get("scopes", [])
        return "*" in scopes or required in scopes
