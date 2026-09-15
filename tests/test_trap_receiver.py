"""TrapReceiver.handle_trap — classify + store + alert + rate-limit (no pysnmp)."""
import configparser
from aruba_agent.trap_receiver import TrapReceiver


class SW:
    def __init__(self, name, host): self.name=name; self.host=host
class State:
    def __init__(self, sws): self.switches={s.name: s for s in sws}
class FakeStore:
    def __init__(self): self.traps=[]
    def save_trap(self, doc): self.traps.append(doc)
class FakeNotifier:
    def __init__(self): self.sent=[]
    def send(self, subject, body): self.sent.append((subject, body))

def _cfg(**over):
    c=configparser.ConfigParser(); c["traps"]={"enabled":"true", **over}; return c

def _rx(store=None, notif=None, **cfgover):
    st=State([SW("core1","10.0.0.1")])
    return TrapReceiver(_cfg(**cfgover), st, store or FakeStore(), notif or FakeNotifier())

LINKDOWN="1.3.6.1.6.3.1.1.5.3"
COLDSTART="1.3.6.1.6.3.1.1.5.1"


def test_maps_source_ip_to_switch_name():
    store=FakeStore(); rx=_rx(store)
    doc=rx.handle_trap("10.0.0.1", COLDSTART, [])
    assert doc["switch"]=="core1" and store.traps[0]["switch"]=="core1"
    # unknown source -> keep the IP
    assert rx.handle_trap("192.168.9.9", COLDSTART, [])["switch"]=="192.168.9.9"


def test_critical_trap_stores_and_alerts():
    store=FakeStore(); notif=FakeNotifier(); rx=_rx(store, notif)
    rx.handle_trap("10.0.0.1", COLDSTART, [])
    assert len(store.traps)==1
    assert len(notif.sent)==1 and "coldStart" in notif.sent[0][0]


def test_link_trap_stores_but_no_alert_under_critical():
    store=FakeStore(); notif=FakeNotifier(); rx=_rx(store, notif)
    rx.handle_trap("10.0.0.1", LINKDOWN, [("1.3.6.1.2.1.2.2.1.1.7","7")])
    assert len(store.traps)==1 and store.traps[0]["ifindex"]=="7"
    assert notif.sent==[]                       # store-only under critical


def test_linkdown_alerts_under_linkdown_policy():
    notif=FakeNotifier(); rx=_rx(notif=notif, alert_policy="critical+linkdown")
    rx.handle_trap("10.0.0.1", LINKDOWN, [("1.3.6.1.2.1.2.2.1.1.7","7")])
    assert len(notif.sent)==1


def test_alert_dedup_suppresses_repeat():
    notif=FakeNotifier(); rx=_rx(notif=notif, alert_dedup_seconds="300")
    for _ in range(4):
        rx.handle_trap("10.0.0.1", COLDSTART, [])
    assert len(notif.sent)==1                   # deduped within window
    assert len(rx.store.traps)==4               # but all stored


def test_none_policy_never_alerts():
    notif=FakeNotifier(); rx=_rx(notif=notif, alert_policy="none")
    rx.handle_trap("10.0.0.1", COLDSTART, [])
    assert notif.sent==[] and len(rx.store.traps)==1


def test_handle_trap_never_raises_on_store_failure():
    class BadStore:
        def save_trap(self, doc): raise RuntimeError("mongo down")
    rx=_rx(store=BadStore())
    doc=rx.handle_trap("10.0.0.1", COLDSTART, [])   # must not raise
    assert doc["name"]=="coldStart"
