"""
Tests for the AOS-CX `show arp` parser in tasks/arp.py.

This is the parser we fixed in v3.0.0 to handle the modern AOS-CX
columnar layout — and the parser whose behaviour the dashboard's ARP
discovery relies on. Worth a real test surface so any future tweak
catches the broadcast / permanent / state-shift edge cases.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from aruba_agent.tasks.arp import ArpDiscoveryTask


def _task() -> ArpDiscoveryTask:
    """
    Build a minimal task instance. Section-proxy-like dicts are good
    enough for parser-only tests; we never call .run(), so the
    config/state plumbing is irrelevant.
    """
    return ArpDiscoveryTask(
        name="test-loc",
        sec={"routers": "1.2.3.4", "ip_list": "/tmp/none",
             "output_dir": "/tmp/none", "retention_days": "30"},
        creds={"username": "admin", "password": ""},
        state=MagicMock(),
    )


def test_parses_modern_reachable_row():
    text = (
        "IPv4 Address     MAC                Port     Physical Port    State\n"
        "----------------------------------------------------------------------\n"
        "10.40.176.120    d0:8e:79:03:e0:a2  vlan218  lag13            reachable\n"
    )
    out = _task()._parse_arp(text)
    assert out == [{
        "ip":   "10.40.176.120",
        "mac":  "d0:8e:79:03:e0:a2",
        "type": "vlan218",
        "port": "lag13",
    }]


def test_drops_broadcast_ff_entries():
    """Broadcast / permanent MAC rows are not real hosts and should be
    filtered out before we write the CSV."""
    text = (
        "10.41.17.255     FF:FF:FF:FF:FF:FF  vlan236                   permanent\n"
    )
    assert _task()._parse_arp(text) == []


def test_handles_missing_physical_port_column():
    """Rows without a physical port have the state word sitting in
    parts[3]. The parser must NOT treat that as a port."""
    text = (
        "10.41.17.100     aa:bb:cc:dd:ee:ff  vlan236                   permanent\n"
    )
    out = _task()._parse_arp(text)
    assert len(out) == 1
    assert out[0]["port"] == ""
    assert out[0]["type"] == "vlan236"


def test_ignores_header_and_separator_lines():
    text = """
IPv4 Address     MAC                Port     Physical Port    State
----------------------------------------------------------------------

10.40.176.120    d0:8e:79:03:e0:a2  vlan218  lag13            reachable
"""
    out = _task()._parse_arp(text)
    assert len(out) == 1
    assert out[0]["ip"] == "10.40.176.120"


def test_ignores_rows_with_bad_mac_format():
    """A row whose MAC isn't a valid 6-octet hex MAC should be silently
    dropped — never error out the whole parse."""
    text = (
        "10.0.0.1    not-a-mac-at-all  vlan1  1/1/1  reachable\n"
        "10.0.0.2    aa:bb:cc:dd:ee:ff vlan1  1/1/2  reachable\n"
    )
    out = _task()._parse_arp(text)
    assert [e["ip"] for e in out] == ["10.0.0.2"]


def test_multiple_entries_parse_in_order():
    text = (
        "10.0.0.10  aa:bb:cc:00:00:01  vlan10  1/1/1   reachable\n"
        "10.0.0.11  aa:bb:cc:00:00:02  vlan10  1/1/2   reachable\n"
        "10.0.0.12  aa:bb:cc:00:00:03  vlan10  lag5    stale\n"
    )
    out = _task()._parse_arp(text)
    assert len(out) == 3
    assert out[0]["port"] == "1/1/1"
    assert out[2]["port"] == "lag5"
