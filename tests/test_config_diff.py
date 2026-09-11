"""config_diff tests — pure diff logic + version listing over cleartext .cfg files."""
import os
from aruba_agent import config_diff as cd


def _write(root, host, fname, text):
    d = os.path.join(root, host); os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, fname), "w") as f:
        f.write(text)


def test_unified_and_counts():
    a = "hostname sw1\nvlan 10\nntp server 1.1.1.1\n"
    b = "hostname sw1\nvlan 10\nvlan 20\nntp server 2.2.2.2\n"
    diff = cd.unified(a, b, "old", "new")
    assert "+vlan 20" in diff
    assert "-ntp server 1.1.1.1" in diff and "+ntp server 2.2.2.2" in diff
    added, removed = cd._count(diff)
    assert added == 2 and removed == 1


def test_list_versions_newest_first(tmp_path):
    root = str(tmp_path)
    _write(root, "sw1", "sw1-startup-config-2026-01-01_000000.cfg", "a")
    _write(root, "sw1", "sw1-startup-config-2026-01-02_000000.cfg", "b")
    v = cd.list_versions(root, "sw1")
    assert v[0].endswith("2026-01-02_000000.cfg")   # newest first
    assert len(v) == 2
    assert cd.list_versions(root, "nope") == []


def test_changed_since_previous(tmp_path):
    root = str(tmp_path)
    _write(root, "sw1", "sw1-startup-config-2026-01-01_000000.cfg", "hostname sw1\nvlan 10\n")
    _write(root, "sw1", "sw1-startup-config-2026-01-02_000000.cfg", "hostname sw1\nvlan 10\nvlan 20\n")
    rec = cd.changed_since_previous(root, "sw1")
    assert rec["changed"] is True and rec["added"] == 1 and rec["removed"] == 0
    assert "+vlan 20" in rec["diff"]


def test_unchanged_config(tmp_path):
    root = str(tmp_path)
    same = "hostname sw1\nvlan 10\n"
    _write(root, "sw1", "sw1-startup-config-2026-01-01_000000.cfg", same)
    _write(root, "sw1", "sw1-startup-config-2026-01-02_000000.cfg", same)
    rec = cd.changed_since_previous(root, "sw1")
    assert rec["changed"] is False and rec["added"] == 0 and rec["diff"] == ""


def test_single_version_returns_none(tmp_path):
    root = str(tmp_path)
    _write(root, "sw1", "sw1-startup-config-2026-01-01_000000.cfg", "x")
    assert cd.changed_since_previous(root, "sw1") is None


def test_detect_changes_dedupes_and_filters(tmp_path):
    root = str(tmp_path)
    # sw1 changed, sw2 unchanged
    _write(root, "sw1", "sw1-startup-config-2026-01-01_000000.cfg", "a\n")
    _write(root, "sw1", "sw1-startup-config-2026-01-02_000000.cfg", "a\nb\n")
    _write(root, "sw2", "sw2-startup-config-2026-01-01_000000.cfg", "z\n")
    _write(root, "sw2", "sw2-startup-config-2026-01-02_000000.cfg", "z\n")
    changes = cd.detect_changes(root, ["sw1", "sw2", "sw1"])   # dupe sw1 ignored
    assert [c["hostname"] for c in changes] == ["sw1"]


def test_format_change_email_truncates(tmp_path):
    changes = [{"hostname": "sw1", "prev": "p", "curr": "c", "changed": True,
                "added": 200, "removed": 0,
                "diff": "\n".join(f"+line{i}" for i in range(200))}]
    body = cd.format_change_email(changes, max_lines_per_device=50)
    assert "sw1" in body and "+200 / -0 lines" in body
    assert "diff truncated at 50 lines" in body
