"""
Tests for aruba_agent.snmp_profiles — the multi-credential SNMPv3
registry. The config-parsing logic has multiple shapes (legacy single
[snmp], modern [snmp.<name>] subsections) and a backward-compat path
that's worth pinning down with tests.
"""

from __future__ import annotations

import configparser

from aruba_agent.snmp_profiles import (
    SnmpProfile,
    SnmpProfileRegistry,
    from_config,
)


def _cfg(text: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    cfg.read_string(text)
    return cfg


def test_disabled_snmp_returns_empty_registry():
    cfg = _cfg("[snmp]\nenabled = false\nusername = nets\nauth_password = x\n")
    registry = from_config(cfg)
    assert len(registry) == 0


def test_missing_snmp_section_returns_empty_registry():
    cfg = _cfg("[other]\nfoo = bar\n")
    registry = from_config(cfg)
    assert len(registry) == 0


def test_legacy_single_section_becomes_default_profile():
    cfg = _cfg("""[snmp]
enabled = true
username = nets
auth_protocol = SHA
auth_password = AuthPass
priv_protocol = AES128
priv_password = PrivPass
context_name = network
""")
    registry = from_config(cfg)
    assert len(registry) == 1
    default = registry.default()
    assert default is not None
    assert default.name == "default"
    assert default.creds.username == "nets"
    assert default.creds.context_name == "network"
    assert default.creds.security_level == "authPriv"


def test_modern_multiple_subsections():
    cfg = _cfg("""[snmp]
enabled = true
default_profile = aruba

[snmp.aruba]
username = nets
auth_password = Auth1
priv_password = Priv1
context_name = network

[snmp.cisco]
username = nets
auth_password = Auth2
priv_password = Priv2
context_name =
""")
    registry = from_config(cfg)
    assert len(registry) == 2
    assert "aruba" in registry
    assert "cisco" in registry
    assert registry.default_name == "aruba"
    # Names are returned with the default first.
    names = registry.names()
    assert names[0] == "aruba"
    assert set(names) == {"aruba", "cisco"}


def test_invalid_default_profile_falls_back_to_first():
    cfg = _cfg("""[snmp]
enabled = true
default_profile = does-not-exist

[snmp.only]
username = nets
auth_password = X
""")
    registry = from_config(cfg)
    # default_name is normalised to a profile that actually exists.
    assert registry.default() is not None
    assert registry.default().name == "only"


def test_blank_username_skips_profile():
    """A subsection without a username can't authenticate — should be
    silently dropped so it doesn't poison the registry."""
    cfg = _cfg("""[snmp]
enabled = true

[snmp.broken]
username =
auth_password = X
""")
    registry = from_config(cfg)
    assert "broken" not in registry


def test_security_level_derives_from_filled_fields():
    """The SnmpV3Credentials.security_level @property is the contract
    every poll path relies on — let's not let it regress."""
    p_full = SnmpProfile(
        name="x",
        creds=type(
            "C", (),
            {
                "username": "u",
                "auth_password": "a",
                "priv_password": "p",
                # We don't need the real dataclass — just the property.
            },
        )(),  # pragma: no cover (smoke shape, not exercised)
    )
    # Use the real class to get the real @property:
    from aruba_agent.snmp import SnmpV3Credentials
    authpriv = SnmpV3Credentials(username="u", auth_password="a", priv_password="p")
    authonly = SnmpV3Credentials(username="u", auth_password="a")
    none     = SnmpV3Credentials(username="u")
    assert authpriv.security_level == "authPriv"
    assert authonly.security_level == "authNoPriv"
    assert none.security_level     == "noAuthNoPriv"
