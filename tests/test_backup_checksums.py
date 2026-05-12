"""
Tests for T2.2 — backup file SHA-256 verifier.
"""

from __future__ import annotations

import hashlib
import os

from aruba_agent.tasks.backup import verify_backups


def _write_pair(host_dir: str, basename: str, data: bytes,
                expected_data: bytes = None) -> None:
    """
    Write <basename>.cfg + matching .sha256 sidecar. If ``expected_data``
    is given, the sidecar is computed against THAT instead of data —
    useful for simulating tampered / corrupted backups.
    """
    cfg_path = os.path.join(host_dir, basename + ".cfg")
    with open(cfg_path, "wb") as f:
        f.write(data)
    digest = hashlib.sha256(expected_data if expected_data is not None else data).hexdigest()
    with open(cfg_path + ".sha256", "w", encoding="ascii") as f:
        f.write(f"{digest}  {os.path.basename(cfg_path)}\n")


def test_clean_directory_passes(tmp_path):
    host = tmp_path / "sw01"
    host.mkdir()
    _write_pair(str(host), "sw01-startup-config-2026-01-01_120000", b"contents-A")
    _write_pair(str(host), "sw01-startup-config-2026-01-02_120000", b"contents-B")
    ok, bad, bad_paths = verify_backups(str(tmp_path))
    assert ok == 2
    assert bad == 0
    assert bad_paths == []


def test_tampered_file_is_flagged(tmp_path):
    host = tmp_path / "sw01"
    host.mkdir()
    # Sidecar computed against "good", but the .cfg actually holds "bad"
    _write_pair(
        str(host),
        "sw01-startup-config-2026-01-01_120000",
        b"BAD-tampered",
        expected_data=b"good",
    )
    ok, bad, bad_paths = verify_backups(str(tmp_path))
    assert ok == 0
    assert bad == 1
    assert len(bad_paths) == 1
    assert "2026-01-01" in bad_paths[0]


def test_missing_sidecar_is_not_an_error(tmp_path):
    """Files without sidecars predate T2.2; they should be reported in
    the log but not counted as bad — running the backup task once more
    will create their sidecars."""
    host = tmp_path / "sw01"
    host.mkdir()
    cfg = host / "sw01-startup-config-2025-12-01_120000.cfg"
    cfg.write_bytes(b"legacy-no-sidecar")
    ok, bad, _ = verify_backups(str(tmp_path))
    assert ok == 0
    assert bad == 0


def test_handles_unreadable_sidecar(tmp_path):
    host = tmp_path / "sw01"
    host.mkdir()
    cfg = host / "sw01-startup-config-2026-01-01_120000.cfg"
    cfg.write_bytes(b"contents")
    # Malformed sidecar — empty file
    (host / cfg.name).with_suffix(".cfg.sha256").write_text("")
    ok, bad, bad_paths = verify_backups(str(tmp_path))
    # Malformed sidecar should count as bad — we can't trust it.
    assert ok == 0
    assert bad == 1


def test_returns_zero_when_path_missing(tmp_path):
    ok, bad, paths = verify_backups(str(tmp_path / "does-not-exist"))
    assert ok == 0
    assert bad == 0
    assert paths == []
