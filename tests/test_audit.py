"""
Tests for aruba_agent.audit — the structured audit log shipped in T1.3.

Covers: line formatting, value quoting, mode 0600 enforcement, and
"never raises" guarantee even when the underlying file goes away.
"""

from __future__ import annotations

import os

import pytest

from aruba_agent import audit as audit_mod
from aruba_agent.audit import AuditLogger, _quote, _ANON


# ─── pure-function tests ────────────────────────────────────────────────────

def test_quote_plain_value():
    assert _quote("plain") == "plain"


def test_quote_value_with_space():
    assert _quote("with space") == '"with space"'


def test_quote_value_with_equals():
    assert _quote("a=b") == '"a=b"'


def test_quote_value_with_quote_escapes():
    assert _quote('he said "hi"') == r'"he said \"hi\""'


def test_quote_none_and_empty_become_dash():
    assert _quote(None) == _ANON == "-"
    assert _quote("") == _ANON


def test_quote_handles_non_strings():
    assert _quote(42) == "42"
    assert _quote(3.14) == "3.14"


# ─── AuditLogger end-to-end ─────────────────────────────────────────────────

@pytest.fixture()
def audit(tmp_path):
    """Fresh AuditLogger backed by a temp file."""
    log = AuditLogger()
    log.install(str(tmp_path / "audit.log"))
    yield log


def test_record_writes_one_line(audit, tmp_path):
    audit.record("login.success", user="alice", ip="10.0.0.5")
    content = (tmp_path / "audit.log").read_text()
    lines = content.strip().splitlines()
    assert len(lines) == 1
    line = lines[0]
    # Components we care about, regardless of timestamp shape.
    assert "user=alice" in line
    assert "event=login.success" in line
    assert "ip=10.0.0.5" in line


def test_record_uses_dash_for_anonymous_actor(audit, tmp_path):
    audit.record("login.failed", user=None, username="admin", reason="bad")
    line = (tmp_path / "audit.log").read_text().strip()
    assert " user=- " in line
    assert "username=admin" in line


def test_record_quotes_values_with_spaces(audit, tmp_path):
    audit.record("settings.smtp.save", user="bob", host="mail server one")
    line = (tmp_path / "audit.log").read_text().strip()
    assert 'host="mail server one"' in line


def test_record_skips_none_details(audit, tmp_path):
    """A None value in **details shouldn't appear as 'reason=-'."""
    audit.record("login.success", user="alice", reason=None, ip="10.0.0.1")
    line = (tmp_path / "audit.log").read_text().strip()
    assert "reason" not in line
    assert "ip=10.0.0.1" in line


def test_record_never_raises_when_file_disappears(tmp_path):
    """If the audit log path becomes unwritable, record() should swallow
    the failure rather than break the action being audited."""
    log = AuditLogger()
    log.install(str(tmp_path / "audit.log"))
    # Yank the handler out from under it.
    log._handler = None        # type: ignore[attr-defined]
    # Must not raise.
    log.record("login.success", user="alice")


def test_audit_log_is_mode_0600(audit, tmp_path):
    audit.record("login.success", user="alice")
    mode = os.stat(tmp_path / "audit.log").st_mode & 0o777
    assert oct(mode) == "0o600"


def test_module_singleton_exists():
    """The convenience `audit` re-export should be a real AuditLogger
    so consumers can `from aruba_agent.audit import audit` and call
    audit.record() without further setup."""
    assert isinstance(audit_mod.audit, AuditLogger)
