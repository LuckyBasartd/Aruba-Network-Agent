"""ThresholdEvaluator — sustained breach, dedup, recovery, scope."""
from aruba_agent.thresholds import ThresholdEvaluator, match_scope


class Clock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t


def _rule(**over):
    r = dict(name="r", enabled=True, metric="if_util_in", operator=">", value=90.0,
             duration_s=120, severity="warning", include="", exclude="")
    r.update(over); return r


def _sample(v, device="sw1", host="10.0.0.1", metric="if_util_in", instance="1/1/1"):
    return dict(device=device, host=host, metric=metric, value=v, instance=instance)


def test_no_alert_below_threshold():
    ev = ThresholdEvaluator(Clock())
    assert ev.evaluate([_rule()], [_sample(50)]) == []


def test_sustained_breach_fires_once_then_dedups():
    clk = Clock(); ev = ThresholdEvaluator(clk)
    rules = [_rule(duration_s=120)]
    # t=1000: breach starts, not yet sustained -> no event
    assert ev.evaluate(rules, [_sample(95)]) == []
    # t=1060: still under duration -> no event
    clk.t = 1060; assert ev.evaluate(rules, [_sample(96)]) == []
    # t=1120: >=120s sustained -> FIRE
    clk.t = 1120; evs = ev.evaluate(rules, [_sample(97)])
    assert len(evs) == 1 and evs[0]["type"] == "fire" and evs[0]["severity"] == "warning"
    # t=1180: still breaching -> deduped, no repeat
    clk.t = 1180; assert ev.evaluate(rules, [_sample(98)]) == []
    assert len(ev.active_alerts()) == 1


def test_recovery_clears():
    clk = Clock(); ev = ThresholdEvaluator(clk)
    rules = [_rule(duration_s=0)]     # immediate
    fire = ev.evaluate(rules, [_sample(95)])
    assert fire and fire[0]["type"] == "fire"
    clk.t = 1200
    clr = ev.evaluate(rules, [_sample(10)])
    assert len(clr) == 1 and clr[0]["type"] == "clear"
    assert ev.active_alerts() == []


def test_breach_reset_before_duration_does_not_fire():
    clk = Clock(); ev = ThresholdEvaluator(clk)
    rules = [_rule(duration_s=120)]
    ev.evaluate(rules, [_sample(95)])          # breach starts
    clk.t = 1060; ev.evaluate(rules, [_sample(50)])   # recovers before duration
    clk.t = 1120; assert ev.evaluate(rules, [_sample(95)]) == []  # new breach, timer reset


def test_scope_include_exclude():
    ev = ThresholdEvaluator(Clock())
    rule = _rule(duration_s=0, include="10.40.0.0/24")
    assert ev.evaluate([rule], [_sample(95, host="10.0.0.1")]) == []          # out of scope
    evs = ev.evaluate([rule], [_sample(95, host="10.40.0.9")])
    assert len(evs) == 1
    # exclude wins
    ev2 = ThresholdEvaluator(Clock())
    rule2 = _rule(duration_s=0, exclude="sw-core")
    assert ev2.evaluate([rule2], [_sample(95, device="sw-core")]) == []


def test_per_instance_independent():
    clk = Clock(); ev = ThresholdEvaluator(clk)
    rules = [_rule(duration_s=0)]
    evs = ev.evaluate(rules, [_sample(95, instance="1/1/1"), _sample(95, instance="1/1/2")])
    assert len(evs) == 2 and {e["instance"] for e in evs} == {"1/1/1", "1/1/2"}


def test_disabled_rule_ignored():
    ev = ThresholdEvaluator(Clock())
    assert ev.evaluate([_rule(duration_s=0, enabled=False)], [_sample(95)]) == []


def test_less_than_operator_for_health():
    ev = ThresholdEvaluator(Clock())
    rule = _rule(metric="memory", operator="<", value=10.0, duration_s=0)
    # free memory % below 10 -> fire
    evs = ev.evaluate([rule], [_sample(5, metric="memory", instance="")])
    assert len(evs) == 1 and evs[0]["metric"] == "memory"


def test_match_scope_helper():
    assert match_scope("sw1", "10.0.0.1", "", "") is True
    assert match_scope("sw1", "10.40.0.5", "10.40.0.0/24", "") is True
    assert match_scope("sw1", "10.0.0.5", "10.40.0.0/24", "") is False
