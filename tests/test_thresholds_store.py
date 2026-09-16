"""ThresholdStore — CRUD + validation + persistence."""
import json
from aruba_agent.thresholds_store import ThresholdStore


def test_save_validation(tmp_path):
    st = ThresholdStore(str(tmp_path / "th.json"))
    ok, err = st.save_rule("bad metric", "nope", ">", 90)
    assert not ok and "metric" in err
    ok, err = st.save_rule("bad op", "cpu", "==", 90)
    assert not ok and "operator" in err
    ok, err = st.save_rule("bad val", "cpu", ">", "high")
    assert not ok and "number" in err
    ok, err = st.save_rule("", "cpu", ">", 90)
    assert not ok and "name" in err


def test_save_get_list_remove(tmp_path):
    p = tmp_path / "th.json"
    st = ThresholdStore(str(p))
    ok, err = st.save_rule("uplink-in", "if_util_in", ">", 90, duration_s=300,
                           severity="warning", include="10.40.0.0/24", added_by="mv")
    assert ok and err == ""
    r = st.get("uplink-in")
    assert r["metric"] == "if_util_in" and r["value"] == 90.0 and r["enabled"] is True
    assert r["include"] == "10.40.0.0/24" and r["created"]

    st.save_rule("cpu-crit", "cpu", ">=", 95, severity="critical")
    names = [r["name"] for r in st.list_rules()]
    assert names == ["uplink-in", "cpu-crit"] or set(names) == {"uplink-in", "cpu-crit"}
    assert len(st.list_rules()) == 2

    # persisted + reloads
    st2 = ThresholdStore(str(p))
    assert st2.get("cpu-crit")["severity"] == "critical"
    # file is valid json with mode 600
    assert json.loads(p.read_text())["rules"]
    assert oct(p.stat().st_mode)[-3:] == "600"


def test_enable_and_remove(tmp_path):
    st = ThresholdStore(str(tmp_path / "th.json"))
    st.save_rule("r1", "temperature", ">", 65)
    assert st.set_enabled("r1", False) is True
    assert st.get("r1")["enabled"] is False
    assert st.list_rules(enabled_only=True) == []
    assert st.set_enabled("nope", False) is False
    assert st.remove("r1") is True and st.get("r1") is None
    assert st.remove("r1") is False
