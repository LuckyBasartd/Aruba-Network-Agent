"""traps.py — classification + alert-policy decisions."""
from aruba_agent import traps


def test_generic_traps_classify():
    assert traps.classify_trap("1.3.6.1.6.3.1.1.5.1")["name"] == "coldStart"
    assert traps.classify_trap("1.3.6.1.6.3.1.1.5.3")["category"] == "link"
    assert traps.classify_trap("1.3.6.1.6.3.1.1.5.5")["category"] == "auth"
    up = traps.classify_trap("1.3.6.1.6.3.1.1.5.4")
    assert up["name"] == "linkUp" and up["severity"] == "info"


def test_linkdown_extracts_ifindex():
    vb = [("1.3.6.1.2.1.2.2.1.1.7", "7"), ("1.3.6.1.2.1.2.2.1.8.7", "2")]
    rec = traps.classify_trap("1.3.6.1.6.3.1.1.5.3", vb)
    assert rec["name"] == "linkDown" and rec["ifindex"] == "7"


def test_enterprise_hardware_detection():
    vb = [("1.3.6.1.4.1.11.2.14.11.5.1.1", "Power supply 1 failed")]
    rec = traps.classify_trap("1.3.6.1.4.1.11.2.14.11.999", vb, name_hint="")
    assert rec["category"] == "hardware" and rec["severity"] == "critical"
    # fan warning (no down-word) -> warning, still hardware
    vb2 = [("x", "Fan tray inserted")]
    assert traps.classify_trap("1.3.6.1.4.1.9.999", vb2)["severity"] == "warning"


def test_unknown_trap_is_other_info():
    rec = traps.classify_trap("1.3.6.1.4.1.9.9.999", [("x", "some vendor event")])
    assert rec["category"] == "other" and rec["severity"] == "info"


def test_should_alert_critical_policy():
    cold = traps.classify_trap("1.3.6.1.6.3.1.1.5.1")
    warm = traps.classify_trap("1.3.6.1.6.3.1.1.5.2")
    ld   = traps.classify_trap("1.3.6.1.6.3.1.1.5.3", [("1.3.6.1.2.1.2.2.1.1.7","7")])
    auth = traps.classify_trap("1.3.6.1.6.3.1.1.5.5")
    hw   = traps.classify_trap("1.3.6.1.4.1.11.999", [("x","PSU failed")])
    assert traps.should_alert(cold, "critical") is True
    assert traps.should_alert(warm, "critical") is False       # warmStart quiet
    assert traps.should_alert(ld,   "critical") is False       # link store-only
    assert traps.should_alert(auth, "critical") is True
    assert traps.should_alert(hw,   "critical") is True


def test_should_alert_link_and_none_policies():
    ld = traps.classify_trap("1.3.6.1.6.3.1.1.5.3", [("1.3.6.1.2.1.2.2.1.1.1","1")])
    lu = traps.classify_trap("1.3.6.1.6.3.1.1.5.4", [("1.3.6.1.2.1.2.2.1.1.1","1")])
    hw = traps.classify_trap("1.3.6.1.4.1.11.999", [("x","fan failed")])
    assert traps.should_alert(ld, "critical+linkdown") is True
    assert traps.should_alert(lu, "critical+linkdown") is False  # linkUp never
    assert traps.should_alert(hw, "none") is False               # none = silent
