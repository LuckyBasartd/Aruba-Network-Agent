"""
Tests for aruba_agent.secrets_store — the v3.0.1 Fernet-backed
encryption layer for config.ini.

Covers: encrypt/decrypt roundtrip, idempotency, empty-value handling,
the on-disk auto-migration (incl. backup creation + re-run no-op),
and the cfg_get helper.
"""

from __future__ import annotations

import configparser
import os

import pytest

from aruba_agent import secrets_store


@pytest.fixture()
def sm(tmp_path):
    """
    Build a SecretManager backed by a fresh master key in tmp_path,
    install it as the process-wide singleton for the duration of the
    test, and tear it down afterwards so the next test starts clean.
    """
    key_path = tmp_path / "master.key"
    manager = secrets_store.SecretManager(str(key_path))
    secrets_store.install(manager)
    yield manager
    secrets_store.install(None)  # type: ignore[arg-type]


def test_master_key_is_created_with_correct_mode(tmp_path):
    key_path = tmp_path / "master.key"
    secrets_store.SecretManager(str(key_path))
    assert key_path.exists()
    # mode 600 — readable only by the agent user
    assert oct(os.stat(key_path).st_mode & 0o777) == "0o600"


def test_encrypt_decrypt_roundtrip(sm):
    pw = "SuperSecret!#@$%^&*()_+ with spaces"
    enc = sm.encrypt(pw)
    assert enc.startswith("enc:")
    assert sm.decrypt(enc) == pw


def test_encrypt_is_idempotent(sm):
    """Re-encrypting an already-encrypted value is a no-op."""
    enc1 = sm.encrypt("hello")
    enc2 = sm.encrypt(enc1)
    assert enc1 == enc2


def test_decrypt_passes_cleartext_through(sm):
    """Values without the enc: prefix are returned unchanged so the
    migration path can run on a partially-migrated config."""
    assert sm.decrypt("cleartext-value") == "cleartext-value"
    assert sm.decrypt("") == ""


def test_empty_string_stays_empty(sm):
    assert sm.encrypt("") == ""
    assert sm.decrypt("") == ""


def test_is_encrypted_predicate():
    assert secrets_store.is_encrypted("enc:abc")
    assert not secrets_store.is_encrypted("plain")
    assert not secrets_store.is_encrypted("")
    assert not secrets_store.is_encrypted(None)  # type: ignore[arg-type]


def test_module_level_decrypt_handles_missing_manager(monkeypatch):
    """
    If we encounter an enc:... value but no SecretManager is installed
    (e.g. cryptography missing on the host), we return empty string
    rather than the ciphertext so the caller's "missing credential"
    code path runs cleanly instead of trying to log in with garbage.
    """
    monkeypatch.setattr(secrets_store, "_INSTANCE", None)
    assert secrets_store.decrypt("enc:not-real") == ""
    # Cleartext still passes through.
    assert secrets_store.decrypt("plain") == "plain"


def test_migration_encrypts_known_fields(tmp_path, sm):
    cfg_path = tmp_path / "config.ini"
    cfg_path.write_text(
        """# header comment
[credentials]
username = admin
password = MyClearPass

[smtp]
enabled = true
password = SmtpPass

[radius]
secret = RadiusShared

[snmp.aruba]
username = nets
auth_password = AuthPass
priv_password = PrivPass

[web]
secret_key = abc123
"""
    )
    changed = secrets_store.migrate_config(str(cfg_path), sm)

    assert ("credentials",       "password")       in changed
    assert ("smtp",              "password")       in changed
    assert ("radius",            "secret")         in changed
    assert ("snmp.aruba",        "auth_password")  in changed
    assert ("snmp.aruba",        "priv_password")  in changed
    assert ("web",               "secret_key")     in changed

    parsed = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    parsed.read(cfg_path)
    assert parsed["credentials"]["password"].startswith("enc:")
    assert parsed["snmp.aruba"]["auth_password"].startswith("enc:")
    assert sm.decrypt(parsed["smtp"]["password"]) == "SmtpPass"


def test_migration_is_idempotent(tmp_path, sm):
    cfg_path = tmp_path / "config.ini"
    cfg_path.write_text("[credentials]\npassword = Hello\n")
    first = secrets_store.migrate_config(str(cfg_path), sm)
    assert first == [("credentials", "password")]
    # Second run finds everything already encrypted → no-op.
    second = secrets_store.migrate_config(str(cfg_path), sm)
    assert second == []


def test_migration_creates_one_time_backup(tmp_path, sm):
    cfg_path = tmp_path / "config.ini"
    cfg_path.write_text("[credentials]\npassword = OriginalCleartext\n")
    secrets_store.migrate_config(str(cfg_path), sm)
    bak = cfg_path.with_suffix(cfg_path.suffix + ".bak")
    assert bak.exists()
    # The .bak should still contain the original cleartext.
    assert "OriginalCleartext" in bak.read_text()


def test_cfg_get_helper(tmp_path, sm):
    """cfg_get should decrypt enc:... values transparently."""
    cfg_path = tmp_path / "config.ini"
    cfg_path.write_text(f"""[smtp]
password = {sm.encrypt("decrypt-me")}
""")
    cfg = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    cfg.read(cfg_path)
    assert secrets_store.cfg_get(cfg, "smtp", "password") == "decrypt-me"
    # Missing sections / keys return the fallback unchanged.
    assert secrets_store.cfg_get(cfg, "nope", "password", fallback="x") == "x"
