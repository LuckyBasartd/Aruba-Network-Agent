"""ThresholdEvalTask — gathers samples, evaluates, notifies (fire+recovery)."""
import configparser
from aruba_agent.tasks.threshold_eval import ThresholdEvalTask


class Clock:
    def __init__(self): self.t=1000.0
    def __call__(self): return self.t

class FakeRules:
    def __init__(self, rules): self._r=rules
    def list_rules(self, enabled_only=False): return self._r

class FakeNotifier:
    def __init__(self): self.sent=[]
    def send(self, subj, body): self.sent.append((subj, body))

def _cfg(**o):
    c=configparser.ConfigParser(); c["thresholds"]={"enabled":"true",**o}; return c

RULE=[dict(name="cpu-high", enabled=True, metric="cpu", operator=">", value=80.0,
           duration_s=0, severity="critical", include="", exclude="")]


def test_fires_and_recovers_through_task():
    clk=Clock()
    samples=[{"device":"sw1","host":"10.0.0.1","metric":"cpu","value":95,"instance":""}]
    src=lambda: samples
    notif=FakeNotifier()
    t=ThresholdEvalTask(_cfg(), FakeRules(RULE), notif, [src], clock=clk)
    t.run()
    assert len(notif.sent)==1 and "ALERT" in notif.sent[0][0] and "CRITICAL" in notif.sent[0][0]
    assert len(t.active_alerts())==1
    # recovery
    samples[0]["value"]=10; clk.t=1100
    t.run()
    assert any("RECOVERED" in s[0] for s in notif.sent)
    assert t.active_alerts()==[]


def test_disabled_task_noop():
    notif=FakeNotifier()
    t=ThresholdEvalTask(_cfg(enabled="false"), FakeRules(RULE), notif,
                        [lambda: [{"device":"s","host":"h","metric":"cpu","value":99,"instance":""}]])
    t.run(); assert notif.sent==[]


def test_no_rules_noop():
    notif=FakeNotifier()
    t=ThresholdEvalTask(_cfg(), FakeRules([]), notif,
                        [lambda: [{"device":"s","host":"h","metric":"cpu","value":99,"instance":""}]])
    t.run(); assert notif.sent==[]


def test_source_failure_isolated():
    def bad(): raise RuntimeError("boom")
    good=lambda: [{"device":"sw1","host":"10.0.0.1","metric":"cpu","value":95,"instance":""}]
    notif=FakeNotifier()
    t=ThresholdEvalTask(_cfg(), FakeRules(RULE), notif, [bad, good], clock=Clock())
    t.run()                                   # bad source must not stop good one
    assert len(notif.sent)==1
