"""
Flask web UI for the Aruba Switch Manager.

Routes:
  GET  /login                       — Login page (RADIUS auth)
  POST /login                       — Validate credentials, establish session
  GET  /logout                      — Destroy session, redirect to login
  GET  /                            — Dashboard (HTML, login-required)
  GET  /api/state                   — Full state JSON (polled by dashboard JS)
  GET  /api/devices                 — Device inventory JSON
  POST /api/backup/trigger          — Fire a manual backup run
  POST /api/scanner/trigger         — Fire a manual network scan
  GET  /api/backups/<hostname>      — List backup files for a switch
  GET  /api/backups/<hostname>/<filename> — Download a specific backup file

Authentication:
  Session-based. Credentials are validated against a RADIUS server (PAP).
  See aruba_agent.auth.RadiusAuthenticator and the [radius] config section.
  Sessions are signed with a server-side secret_key from [web] secret_key.
"""

from __future__ import annotations

import configparser
import functools
import logging
import os
import secrets
import threading
from datetime import timedelta
from typing import Callable, Optional

from flask import (
    Flask,
    abort,
    flash,
    get_flashed_messages,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from aruba_agent.auth  import RadiusAuthenticator
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
    secret_key            = ""
    session_timeout_hours = 8
    secure_cookies        = False
    trust_proxy_headers   = False

    if cfg:
        backup_path           = cfg.get("backup", "backup_path", fallback=backup_path)
        secret_key            = cfg.get("web", "secret_key", fallback="").strip()
        session_timeout_hours = cfg.getint("web", "session_timeout_hours", fallback=8)
        secure_cookies        = cfg.getboolean("web", "secure_cookies", fallback=False)
        trust_proxy_headers   = cfg.getboolean("web", "trust_proxy_headers", fallback=False)

    # A stable secret_key is REQUIRED so sessions survive agent restarts.
    # If the admin forgot to set one, generate an ephemeral one and warn —
    # users will just need to re-login after every restart.
    if not secret_key:
        secret_key = secrets.token_urlsafe(48)
        log.warning(
            "No [web] secret_key configured — generated an ephemeral key. "
            "Sessions will be invalidated on every agent restart. "
            "Set [web] secret_key in config.ini to a long random string."
        )

    app.config["SECRET_KEY"]              = secret_key
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=session_timeout_hours)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"]   = secure_cookies

    # Behind Apache's reverse proxy: trust the X-Forwarded-* headers it
    # sets so request.remote_addr reflects the real client IP, and
    # url_for() generates https:// URLs. We trust exactly one hop —
    # the Apache vhost on the same host. Do NOT enable this when the
    # agent is exposed directly; spoofed headers would defeat audit logs.
    if trust_proxy_headers:
        app.wsgi_app = ProxyFix(  # type: ignore[assignment]
            app.wsgi_app,
            x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1,
        )
        log.info("Web UI: ProxyFix enabled — trusting one upstream proxy hop")

    # RADIUS authenticator — always created; it knows how to self-disable
    # when [radius] is missing or incomplete.
    radius = RadiusAuthenticator(cfg) if cfg else RadiusAuthenticator(configparser.ConfigParser())

    if not radius.is_configured():
        log.warning(
            "Web UI: RADIUS is not configured — login will reject all attempts. "
            "Set [radius] enabled=true and fill in server/secret to enable login."
        )
    else:
        log.info("Web UI: session-based login with RADIUS PAP enabled")

    # ---------------------------------------------------------------- helpers

    def _run_in_thread(fn: Callable, name: str) -> None:
        threading.Thread(target=fn, name=name, daemon=True).start()

    def require_login(fn: Callable) -> Callable:
        """Decorator: redirect unauthenticated users to the login page."""
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get("user"):
                # For API endpoints (JSON) return 401 instead of redirect
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Authentication required"}), 401
                return redirect(url_for("login", next=request.path))
            return fn(*args, **kwargs)
        return wrapper

    # --------------------------------------------------------------- auth routes

    @app.get("/login")
    def login():
        if session.get("user"):
            return redirect(url_for("dashboard"))
        return render_template(
            "login.html",
            radius_configured=radius.is_configured(),
            errors=get_flashed_messages(category_filter=["error"]),
            next_url=request.args.get("next", ""),
        )

    @app.post("/login")
    def login_post():
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        next_url = request.form.get("next", "") or url_for("dashboard")

        # Only redirect to internal paths — blocks open-redirect attacks.
        if not next_url.startswith("/") or next_url.startswith("//"):
            next_url = url_for("dashboard")

        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for("login", next=next_url))

        if not radius.is_configured():
            log.warning("Login attempt rejected — RADIUS not configured (user=%s)", username)
            flash("Authentication service is not configured. Contact your administrator.", "error")
            return redirect(url_for("login", next=next_url))

        if radius.authenticate(username, password):
            session.clear()
            session["user"]   = username
            session.permanent = True
            log.info("Web UI: user=%s logged in from %s", username, request.remote_addr)
            return redirect(next_url)

        log.info("Web UI: failed login attempt user=%s from %s", username, request.remote_addr)
        flash("Invalid username or password.", "error")
        return redirect(url_for("login", next=next_url))

    @app.get("/logout")
    def logout():
        user = session.get("user")
        session.clear()
        if user:
            log.info("Web UI: user=%s logged out", user)
        return redirect(url_for("login"))

    # --------------------------------------------------------------- dashboard

    @app.get("/")
    @require_login
    def dashboard():
        return render_template("dashboard.html", current_user=session.get("user"))

    @app.get("/api/state")
    @require_login
    def api_state():
        return jsonify(state.to_dict())

    @app.get("/api/devices")
    @require_login
    def api_devices():
        with state._lock:
            devices = list(state.device_inventory)
        return jsonify(devices)

    @app.get("/api/whoami")
    @require_login
    def api_whoami():
        return jsonify({"user": session.get("user")})

    @app.post("/api/backup/trigger")
    @require_login
    def api_backup_trigger():
        if backup_fn is None:
            return jsonify({"error": "Backup not configured"}), 503
        _run_in_thread(backup_fn, "manual-backup")
        log.info("Web UI: manual backup triggered by user=%s", session.get("user"))
        return jsonify({"status": "triggered"})

    @app.post("/api/scanner/trigger")
    @require_login
    def api_scanner_trigger():
        if scanner_fn is None:
            return jsonify({"error": "Scanner not configured"}), 503
        _run_in_thread(scanner_fn, "manual-scan")
        log.info("Web UI: manual scan triggered by user=%s", session.get("user"))
        return jsonify({"status": "triggered"})

    @app.get("/api/backups/<hostname>")
    @require_login
    def api_backup_list(hostname: str):
        """Return a sorted list of backup filenames for a switch (newest first)."""
        if not all(c.isalnum() or c in "-_." for c in hostname):
            abort(400)
        host_dir = os.path.join(backup_path, hostname)
        if not os.path.isdir(host_dir):
            return jsonify([])
        files = sorted(
            [f for f in os.listdir(host_dir) if f.endswith(".cfg")],
            reverse=True,
        )
        return jsonify(files)

    @app.get("/api/backups/<hostname>/<filename>")
    @require_login
    def api_backup_download(hostname: str, filename: str):
        """Stream a backup .cfg file as a download."""
        if not all(c.isalnum() or c in "-_." for c in hostname):
            abort(400)
        if not all(c.isalnum() or c in "-_." for c in filename):
            abort(400)
        filepath = os.path.join(backup_path, hostname, filename)
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
    threads: int = 8,
) -> None:
    """
    Start Flask under a production WSGI server in a background daemon thread.

    Uses **waitress** as the WSGI server. Why waitress and not gunicorn:

      * Single-process, multi-threaded — shared in-memory ``AgentState``
        keeps working without forks or IPC.
      * Pure Python, no native dependencies, runs on AlmaLinux without
        compiler toolchain headaches.
      * Doesn't claim signal handlers, so main.py's SIGTERM/SIGINT
        graceful shutdown keeps working.
      * Genuine production server (it's the default for Pyramid).

    Falls back to werkzeug's dev server only if waitress isn't installed
    — with a loud warning so it can't silently happen in production.
    """
    try:
        from waitress import serve  # type: ignore[import]
    except ImportError:
        log.warning(
            "waitress is NOT installed — falling back to werkzeug dev server. "
            "This is fine for local dev but UNSUPPORTED in production. "
            "Run: pip3 install waitress"
        )

        def _run_dev() -> None:
            app.run(host=host, port=port, use_reloader=False, threaded=True)

        threading.Thread(target=_run_dev, name="web-ui-dev", daemon=True).start()
        log.info("Web UI (dev) available at http://%s:%d",
                 host if host != "0.0.0.0" else "localhost", port)
        return

    def _run_prod() -> None:
        # ident= shows up in the Server: response header
        serve(
            app,
            host    = host,
            port    = port,
            threads = threads,
            ident   = "aruba-agent",
            # We sit behind Apache, which already times out idle conns;
            # waitress's default channel_timeout (120s) is fine.
        )

    threading.Thread(target=_run_prod, name="web-ui", daemon=True).start()
    log.info(
        "Web UI (waitress, %d threads) available at http://%s:%d",
        threads, host if host != "0.0.0.0" else "localhost", port,
    )
