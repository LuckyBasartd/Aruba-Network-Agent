"""Scanner new-device diff: exclude already-monitored devices (no false rediscovery)."""
from aruba_agent.tasks.scanner import NetworkScannerTask


def test_diff_excludes_existing_and_known():
    current  = {"10.0.0.1": "a", "10.0.0.2": "b", "10.0.0.3": "c", "10.0.0.4": "d"}
    existing = {"10.0.0.1": "a"}                  # in last night's CSV
    known    = {"10.0.0.2", "10.0.0.3"}           # already monitored
    new = NetworkScannerTask._diff_new(current, existing, known)
    assert set(new) == {"10.0.0.4"}               # only the genuinely-new one


def test_known_device_not_reflagged_when_missing_from_csv():
    # A monitored switch that flapped out of the ping CSV must NOT alert.
    current  = {"10.253.0.64": "vxblock"}         # pinged tonight
    existing = {}                                 # dropped from CSV last run
    known    = {"10.253.0.64"}                    # but it's monitored
    assert NetworkScannerTask._diff_new(current, existing, known) == {}


def test_truly_new_device_still_alerts():
    current  = {"10.9.9.9": "newbox"}
    assert NetworkScannerTask._diff_new(current, {}, set()) == {"10.9.9.9": "newbox"}
    assert NetworkScannerTask._diff_new(current, {}, {"10.0.0.1"}) == {"10.9.9.9": "newbox"}
