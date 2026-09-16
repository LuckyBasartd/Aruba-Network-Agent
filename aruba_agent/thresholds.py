"""
Threshold evaluation engine (pure, stateful, testable).

Feed it the active rules and a batch of metric samples each cycle; it returns
alert *events* — "fire" when a value has breached a rule's threshold for the
rule's sustained duration (anti-flap), and "clear" (recovery) when a previously
fired breach returns to normal. Per-(rule, device, instance) state means a
breach alerts once, not every cycle. No I/O — the caller emails/stores events.

A "sample" is a dict: {device, host, metric, value, instance}
  * device/host  — switch name / IP (host used for CIDR scope matching)
  * metric       — one of thresholds_store.VALID_METRICS
  * value        — numeric
  * instance     — sub-identity (e.g. ifName for per-port metrics; "" for
                   device-level metrics like cpu/memory)
"""

from __future__ import annotations

import ipaddress
import time
from typing import Callable, Dict, List, Optional

_OPS: Dict[str, Callable[[float, float], bool]] = {
    ">":  lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "<":  lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
}


def _csv(v: str) -> List[str]:
    return [x.strip() for x in (v or "").replace(" ", ",").split(",") if x.strip()]


def _host_in(name: str, host: str, patterns: List[str]) -> bool:
    for p in patterns:
        if p == name or p == host:
            return True
        if "/" in p:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(p, strict=False):
                    return True
            except ValueError:
                pass
    return False


def match_scope(name: str, host: str, include: str, exclude: str) -> bool:
    exc = _csv(exclude)
    if exc and _host_in(name, host, exc):
        return False
    inc = _csv(include)
    if inc and not _host_in(name, host, inc):
        return False
    return True


class ThresholdEvaluator:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        # (rule, device, instance) -> {since, alerted, value, severity, ...}
        self._state: Dict[tuple, dict] = {}

    def evaluate(self, rules: List[dict], samples: List[dict]) -> List[dict]:
        now = self._clock()
        events: List[dict] = []
        by_metric: Dict[str, List[dict]] = {}
        for s in samples:
            by_metric.setdefault(s.get("metric"), []).append(s)

        for rule in rules:
            if not rule.get("enabled", True):
                continue
            op = _OPS.get(rule.get("operator"))
            if op is None:
                continue
            try:
                thr = float(rule.get("value"))
                dur = int(rule.get("duration_s", 0) or 0)
            except (TypeError, ValueError):
                continue
            for s in by_metric.get(rule.get("metric"), []):
                dev = s.get("device", "")
                host = s.get("host", dev)
                inst = s.get("instance", "")
                if not match_scope(dev, host, rule.get("include", ""), rule.get("exclude", "")):
                    continue
                val = s.get("value")
                if val is None:
                    continue
                try:
                    val = float(val)
                except (TypeError, ValueError):
                    continue
                key = (rule.get("name"), dev, inst)
                if op(val, thr):
                    st = self._state.get(key)
                    if st is None:
                        st = self._state[key] = {"since": now, "alerted": False,
                                                 "severity": rule.get("severity", "warning")}
                    st["value"] = val
                    if not st["alerted"] and (now - st["since"]) >= dur:
                        st["alerted"] = True
                        events.append(self._event("fire", rule, dev, host, inst, val, now))
                else:
                    st = self._state.pop(key, None)
                    if st and st.get("alerted"):
                        events.append(self._event("clear", rule, dev, host, inst, val, now))
        return events

    def active_alerts(self) -> List[dict]:
        """Currently-firing breaches (for the UI)."""
        out = []
        for (rule, dev, inst), st in self._state.items():
            if st.get("alerted"):
                out.append({"rule": rule, "device": dev, "instance": inst,
                            "value": st.get("value"), "severity": st.get("severity"),
                            "since": st.get("since")})
        return out

    @staticmethod
    def _event(typ, rule, dev, host, inst, val, now) -> dict:
        metric = rule.get("metric")
        where = f"{dev} {inst}".strip()
        if typ == "fire":
            summary = (f"{rule.get('severity','warning').upper()} {rule.get('name')}: "
                       f"{metric}={val} {rule.get('operator')} {rule.get('value')} on {where}")
        else:
            summary = f"RECOVERED {rule.get('name')}: {metric}={val} on {where}"
        return {
            "type": typ, "rule": rule.get("name"), "metric": metric,
            "device": dev, "host": host, "instance": inst,
            "value": val, "threshold": rule.get("value"),
            "operator": rule.get("operator"), "severity": rule.get("severity", "warning"),
            "ts": now, "message": summary,
        }
