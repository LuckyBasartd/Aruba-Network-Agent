"""
Flask web UI for the Aruba Agent.

Routes:
  GET  /                      — Dashboard (HTML)
  GET  /api/state             — Full state JSON (polled by dashboard JS)
  GET  /api/devices           — Device inventory JSON
  POST /api/backup/trigger    — Fire a manual backup run
  POST /api/scanner/trigger   — Fire a manual network scan
"""

from __future__ import annotations

import configparser
import logging
import threading
from typing import Callable, Optional

from flask import Flask, jsonify, render_template, request

from aruba_agent.state import AgentState

log = logging.getLogger(__name__)


def create_app(
    state: AgentState,
    backup_fn:  Optional[Callable] = None,
    scanner_fn: Optional[Callable] = None,
    cfg: Optional[configparser.ConfigParser] = None,
) -> Flask:
    """
    Factory — call once in main.py.

    Parameters
    ----------
    state       Shared AgentState instance.
    backup_fn   Callable to invoke for manual backup (BackupTask.run).
    scanner_fn  Callable to invoke for manual scan (NetworkScannerTask.run).
    cfg         Full config (used to read [web] settings if needed later).
    """
    app = Flask(__name__, template_folder="templates")
    app.config["JSON_SORT_KEYS"] = False

    # ---------------------------------------------------------------- helpers

    def _run_in_thread(fn: Callable, name: str):
        t = threading.Thread(target=fn, name=name, daemon=True)
        t.start()

    # --------------------------------------------------------------- routes

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html")

    @app.get("/api/state")
    def api_state():
        return jsonify(state.to_dict())

    @app.get("/api/devices")
    def api_devices():
        with state._lock:
            devices = list(state.device_inventory)
        return jsonify(devices)

    @app.post("/api/backup/trigger")
    def api_backup_trigger():
        if backup_fn is None:
            return jsonify({"error": "Backup not configured"}), 503
        _run_in_thread(backup_fn, "manual-backup")
        log.info("Web UI: manual backup triggered")
        return jsonify({"status": "triggered"})

    @app.post("/api/scanner/trigger")
    def api_scanner_trigger():
        if scanner_fn is None:
            return jsonify({"error": "Scanner not configured"}), 503
        _run_in_thread(scanner_fn, "manual-scan")
        log.info("Web UI: manual scan triggered")
        return jsonify({"status": "triggered"})

    return app


def start(
    app: Flask,
    host: str = "0.0.0.0",
    port: int  = 8080,
) -> None:
    """Start Flask in a background daemon thread (non-blocking)."""
    def _run():
        # use_reloader=False is required when running inside a thread
        app.run(host=host, port=port, use_reloader=False, threaded=True)

    threading.Thread(target=_run, name="web-ui", daemon=True).start()
    log.info("Web UI available at http://%s:%d", host if host != "0.0.0.0" else "localhost", port)
