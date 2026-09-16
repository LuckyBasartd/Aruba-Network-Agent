"""
Threshold evaluation task — the alerting engine's periodic runner.

Every eval_seconds it: loads enabled rules from the ThresholdStore, gathers
current samples from the registered sources (interface poll, health poll),
runs the ThresholdEvaluator, and emails fire/recovery events via the notifier.
De-duplication and sustained-duration live in the evaluator, so this just
forwards events. active_alerts() feeds the web UI.
"""

from __future__ import annotations

import configparser
import logging
import threading
import time
from typing import Callable, List

from aruba_agent.thresholds import ThresholdEvaluator

log = logging.getLogger(__name__)


class ThresholdEvalTask:
    def __init__(self, cfg: configparser.ConfigParser, rules_store, notifier,
                 sample_sources: List[Callable[[], list]], clock=time.time) -> None:
        t = cfg["thresholds"] if "thresholds" in cfg else {}
        self.enabled      = (t.get("enabled", "false") or "false").lower() == "true"
        self.eval_seconds = max(30, int(t.get("eval_seconds", "60") or "60"))
        self.rules_store  = rules_store
        self.notifier     = notifier
        self.sources      = sample_sources or []
        self.evaluator    = ThresholdEvaluator(clock)
        self._running     = threading.Lock()
        self._lock        = threading.RLock()
        self._last_run    = 0.0
        self._fired_total = 0

    def run(self) -> None:
        if not self.enabled or self.rules_store is None:
            return
        if not self._running.acquire(blocking=False):
            return
        try:
            rules = self.rules_store.list_rules(enabled_only=True)
            if not rules:
                return
            samples: list = []
            for src in self.sources:
                try:
                    samples.extend(src() or [])
                except Exception as exc:
                    log.debug("threshold eval: sample source failed (%s)", exc)
            events = self.evaluator.evaluate(rules, samples)
            for e in events:
                self._notify(e)
            with self._lock:
                self._last_run = time.time()
                self._fired_total += sum(1 for e in events if e["type"] == "fire")
            if events:
                log.info("threshold eval: %d event(s) (%d rules, %d samples)",
                         len(events), len(rules), len(samples))
        finally:
            self._running.release()

    def _notify(self, e: dict) -> None:
        kind = "ALERT" if e["type"] == "fire" else "RECOVERED"
        subj = f"[Network Agent] {e['severity'].upper()} {kind}: {e['rule']}"
        try:
            self.notifier.send(subj, e["message"])
        except Exception as exc:
            log.error("threshold eval: alert email failed (%s)", exc)
        log.info("threshold %s: %s", kind.lower(), e["message"])

    def active_alerts(self) -> list:
        return self.evaluator.active_alerts()
