"""
Coalesces reachability alerts so a simultaneous multi-switch outage
produces ONE email instead of N.

Per kind ("down" / "restored"): the first event starts a collection
window (default 60s); every event of that kind that arrives before the
window closes joins the same email; at flush a single message is sent.
A quiet fleet still gets one email per event (window elapses with one
entry). Thread-safe — every SwitchMonitor thread shares one batcher.

Set window_seconds to 0 to disable batching (send immediately, one per
event) — restores the pre-batching behaviour.
"""

from __future__ import annotations

import logging
import threading
from typing import Dict, List, Tuple

log = logging.getLogger(__name__)

_SEP = "\n" + "_" * 44 + "\n"


class AlertBatcher:
    def __init__(self, notifier, window_seconds: int = 60) -> None:
        self._notifier = notifier
        self._window   = max(0, int(window_seconds))
        self._lock     = threading.Lock()
        self._pending: Dict[str, List[Tuple[str, str]]] = {}   # kind -> [(label, block)]
        self._timers:  Dict[str, threading.Timer]       = {}

    # ─── public ──────────────────────────────────────────────────────────────
    def add(self, kind: str, label: str, block: str) -> None:
        """Queue one reachability event. ``kind`` is 'down'/'restored',
        ``label`` names the switch (for the subject), ``block`` is the
        email body for this one switch."""
        if self._window <= 0:                      # batching disabled
            self._send(kind, [(label, block)])
            return
        with self._lock:
            self._pending.setdefault(kind, []).append((label, block))
            if kind not in self._timers:
                t = threading.Timer(self._window, self._flush, args=(kind,))
                t.daemon = True
                self._timers[kind] = t
                t.start()

    def flush_all(self) -> None:
        """Send any pending batches immediately (e.g. on shutdown)."""
        with self._lock:
            kinds = list(self._pending.keys())
            for t in self._timers.values():
                t.cancel()
            self._timers.clear()
        for kind in kinds:
            self._flush(kind)

    # ─── internal ────────────────────────────────────────────────────────────
    def _flush(self, kind: str) -> None:
        with self._lock:
            entries = self._pending.pop(kind, [])
            self._timers.pop(kind, None)
        if entries:
            self._send(kind, entries)

    def _send(self, kind: str, entries: List[Tuple[str, str]]) -> None:
        labels = [lab for lab, _ in entries]
        if len(entries) == 1:
            body = entries[0][1]
        else:
            body = _SEP.join(block for _, block in entries)
        try:
            self._notifier.send(self._subject(kind, labels), body)
        except Exception as exc:                   # noqa: BLE001
            log.error("AlertBatcher: failed to send %d %s alert(s): %s",
                      len(entries), kind, exc)

    @staticmethod
    def _subject(kind: str, labels: List[str]) -> str:
        word = "RESTORED" if kind == "restored" else "DOWN"
        if len(labels) == 1:
            return f"[Aruba] Switch {word}: {labels[0]}"
        return f"[Aruba] {len(labels)} switches {word}"
