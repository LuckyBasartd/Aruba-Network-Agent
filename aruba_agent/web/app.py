"""
Flask web UI for the Aruba Agent.

Routes:
  GET  /                            — Dashboard (HTML)
  GET  /api/state                   — Full state JSON (polled by dashboard JS)
  GET  /api/devices                 — Device inventory JSON
  POST /api/backup/trigger          — Fire a manual backup run
  POST /api/scanner/trigger         — Fire a manual network scan
  GET  /api/backups/<hostname>      — List backup files for a switch
  GET  /api/backups/<hostname>/<filename> — Download a specific backup file
"""

from __future__ import annotations

import configparser
import logging
import os
import threading
from typing import Callable, Optional

from flask import Flask, jsonify, render_template, send_file, abort

from aruba_agent.state import AgentState

log = logging.getLogger(__name__)


def create_app(
    state: AgentState,
    backup_fn:   Optional[Callable] = None,
    scanner_fn:  Optional[Callable] = None,
    cfg: Optional[configparser.ConfigParser] = None,
) -> Flask:
    app = Flask(__name__, template_folder="templates")
    app.config["JSON_SORT_KEYS"] = False

    backup_path = "/var/lib/aruba-agent/backups"
    if cfg:
        backup_path = cfg.get("backup", "backup_path", fallback=backup_path)

    # ---------------------------------------------------------------- helpers

    def _run_in_thread(fn: Callable, name: str) -> None:
        threading.Thread(target=fn, name=name, daemon=True).start()

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

    @app.get("/api/backups/<hostname>")
    def api_backup_list(hostname: str):
        """Return a sorted list of backup filenames for a switch (newest first)."""
        # Sanitise hostname — only allow safe characters
        if not all(c.isalnum() or c in "-_." for c in hostname):
            abort(400)
        host_dir = os.path.join(backup_path, hostname)
        if not os.path.isdir(host_dir):
            return jsonify([])
        files = sorted(
            [f for f in os.listdir(host_dir) if f.endswith(".cfg")],
            reverse=True,   # newest first
        )
        return jsonify(files)

    @app.get("/api/backups/<hostname>/<filename>")
    def api_backup_download(hostname: str, filename: str):
        """Stream a backup .cfg file as a download."""
        if not all(c.isalnum() or c in "-_." for c in hostname):
            abort(400)
        if not all(c.isalnum() or c in "-_." for c in filename):
            abort(400)
        filepath = os.path.join(backup_path, hostname, filename)
        # Resolve and verify the path stays inside backup_path (path traversal guard)
        real_backup = os.path.realpath(backup_path)
        real_file   = os.path.realpath(filepath)
        if not real_file.startswith(real_backup + os.sep):
            abort(403)
        if not os.path.isfile(real_file):
            abort(404)
        return send_file(real_file, as_attachment=True, download_name=filename)

    return app


def start(
    app: Flask,
    host: str = "0.0.0.0",
    port: int  = 8080,
) -> None:
    """Start Flask in a background daemon thread (non-blocking)."""
    def _run() -> None:
        app.run(host=host, port=port, use_reloader=False, threaded=True)

    threading.Thread(target=_run, name="web-ui", daemon=True).start()
    log.info("Web UI available at http://%s:%d",
             host if host != "0.0.0.0" else "localhost", port)
