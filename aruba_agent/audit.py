"""
Audit logger — separate file from the systemd journal.

Why this exists
---------------
Up through v3.0.1 every "user X did Y" event landed in journald with
the rest of the agent's output and rotated with the journal's standard
rules. That's fine for casual operations work but bad for compliance:
the journal mixes audit events with debug chatter, the retention is
controlled by journald not the operator, and `journalctl | grep` is
awkward to hand to an auditor.

This module writes a *second* copy of every security-relevant event
to a dedicated file (default ``/var/log/aruba-agent/audit.log``,
mode 600, owned by the service account) in a stable line-per-event
format that's easy to grep, easy to ship to a SIEM, and easy to
rotate with the standard logrotate.d toolchain.

Events still go to the regular logger as well — nothing about the
journal output changes. The audit file is additive.

Format
------
Each line is ISO-8601 timestamp + actor + event + key=value details:

    2026-05-11T14:23:01-07:00 user=mvieira event=login.success ip=10.0.0.5
    2026-05-11T14:23:14-07:00 user=mvieira event=settings.smtp.save host=smtp.example.com
    2026-05-11T14:25:02-07:00 user=- event=login.failed username=admin ip=203.0.113.7 reason=bad_password

Values with spaces, =, or " are quoted. ``user=-`` denotes an
anonymous / pre-auth event (failed login, healthz, etc).

Threading
---------
RotatingFileHandler is thread-safe; multiple Flask worker threads
can call ``record()`` concurrently. We hold no extra locks.

Usage
-----
    from aruba_agent.audit import audit
    audit.record("login.success", user="mvieira", ip="10.0.0.5")
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional


log = logging.getLogger(__name__)


# Sentinel used when the event has no associated user (pre-auth events,
# scheduled-task audits, etc). Easier to grep for "user=-" than to
# special-case missing fields in downstream tooling.
_ANON = "-"

# Default path. Operator can override via [agent] audit_log_file in
# config.ini, or by calling install() with an explicit path.
DEFAULT_AUDIT_LOG_PATH = "/var/log/aruba-agent/audit.log"

# RotatingFileHandler limits — match what the shipped logrotate.d
# rule expects. If both are active, logrotate wins for the daily
# rotation cadence and these caps just keep us from filling the disk
# between rotations.
_MAX_BYTES        = 5 * 1024 * 1024     # 5 MB
_BACKUP_COUNT     = 10                   # keep ~50 MB total worst case


# ─── formatting helpers ──────────────────────────────────────────────────────

def _quote(value: Any) -> str:
    """
    Render a single value for the audit line. Strings with spaces,
    quotes, or equals signs are double-quoted with embedded quotes
    escaped. Everything else gets str() and the same rule applies.
    """
    if value is None:
        return _ANON
    text = str(value)
    if not text:
        return _ANON
    needs_quote = any(c in text for c in ' "=\t')
    if not needs_quote:
        return text
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _now_iso() -> str:
    """ISO-8601 with timezone. Local time + offset so an auditor can
    correlate against switch / RADIUS logs without timezone math."""
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


# ─── the logger ──────────────────────────────────────────────────────────────

class AuditLogger:
    """
    Thin wrapper around a RotatingFileHandler that knows how to format
    audit events. One instance per process; ``install()`` creates it
    and ``audit`` re-exports it module-level for convenience.
    """

    def __init__(self) -> None:
        self._lock    = threading.Lock()
        self._handler: Optional[RotatingFileHandler] = None
        self._path:    Optional[Path]                = None

    def install(self, path: str = DEFAULT_AUDIT_LOG_PATH) -> None:
        """
        Open ``path`` for append, ensure mode 600, and remember the
        handle for subsequent ``record()`` calls. Safe to call multiple
        times; subsequent calls reopen the file (useful after logrotate
        rotates without copytruncate).
        """
        with self._lock:
            target = Path(path)
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                # Touch the file so chmod works even on first run.
                target.touch(exist_ok=True)
                try:
                    os.chmod(target, 0o600)
                except OSError:
                    # Non-fatal: the systemd unit's User= may not own
                    # the parent dir on first start. We'll still
                    # write; just can't tighten the mode.
                    pass

                if self._handler is not None:
                    try:
                        self._handler.close()
                    except Exception:
                        pass

                # RotatingFileHandler handles its own locking.
                self._handler = RotatingFileHandler(
                    str(target),
                    maxBytes    = _MAX_BYTES,
                    backupCount = _BACKUP_COUNT,
                    encoding    = "utf-8",
                    delay       = False,
                )
                # Bare line format — we render the structured key=value
                # payload ourselves and pass the whole thing in msg.
                self._handler.setFormatter(logging.Formatter("%(message)s"))
                self._path = target
            except OSError as exc:
                log.warning("Audit: could not open %s for append (%s) — "
                            "audit events will go to the journal only", path, exc)
                self._handler = None
                self._path    = None

    @property
    def path(self) -> Optional[Path]:
        return self._path

    def record(self, event: str, *, user: Optional[str] = None, **details: Any) -> None:
        """
        Emit one audit line. ``event`` is a dotted identifier
        (e.g. ``login.failed``, ``settings.smtp.save``). ``user`` is
        the actor's username, or None for pre-auth events.

        Never raises — audit logging failures cannot block the action
        being audited.
        """
        try:
            parts = [
                _now_iso(),
                f"user={_quote(user) if user else _ANON}",
                f"event={_quote(event)}",
            ]
            for k, v in details.items():
                # Skip None values so callers can pass them through
                # without polluting every line with "reason=-".
                if v is None:
                    continue
                parts.append(f"{k}={_quote(v)}")
            line = " ".join(parts)
        except Exception as exc:  # pragma: no cover — extremely defensive
            log.warning("Audit: could not format event %s (%s)", event, exc)
            return

        handler = self._handler
        if handler is not None:
            try:
                # Reuse the LogRecord machinery so RotatingFileHandler's
                # size check + rollover stays correct.
                record = logging.LogRecord(
                    name    = "audit",
                    level   = logging.INFO,
                    pathname= "",
                    lineno  = 0,
                    msg     = line,
                    args    = None,
                    exc_info= None,
                )
                handler.emit(record)
            except Exception as exc:  # pragma: no cover
                log.warning("Audit: could not write event %s (%s)", event, exc)


# Module-level singleton. Imports cheaply (no file is opened until
# install() is called), so it's safe to import from anywhere.
audit = AuditLogger()
