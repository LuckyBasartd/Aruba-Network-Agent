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

from aruba_agent.auth        import RadiusAuthenticator
from aruba_agent.local_auth  import LocalAuthStore
from aruba_agent.state       import AgentState

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

    # Local credential store — always created. On first start the store
    # bootstraps a default admin/admin entry flagged must_change=true so
    # the operator is forced to set a real password on first login.
    local_store_path = (
        cfg.get("local_auth", "store_file",
                fallback="/var/lib/aruba-agent/users.json")
        if cfg else "/var/lib/aruba-agent/users.json"
    )
    local_auth_enabled = (
        cfg.getboolean("local_auth", "enabled", fallback=True)
        if cfg else True
    )
    local_store = LocalAuthStore(local_store_path)
    if local_auth_enabled:
        local_store.bootstrap_default_admin()

    if local_auth_enabled:
        log.info("Web UI: local authentication enabled (store=%s)", local_store_path)
    if radius.is_configured():
        log.info("Web UI: RADIUS PAP authentication enabled")

    if not local_auth_enabled and not radius.is_configured():
        log.warning(
            "Web UI: NEITHER local auth NOR RADIUS is configured — "
            "login will reject all attempts."
        )

    # ---------------------------------------------------------------- helpers

    def _run_in_thread(fn: Callable, name: str) -> None:
        threading.Thread(target=fn, name=name, daemon=True).start()

    def require_login(fn: Callable) -> Callable:
        """
        Decorator: redirect unauthenticated users to the login page.

        Also intercepts users with `must_change=True` flagged on their
        session and force-redirects them to /change-password until they
        comply. The /change-password and /logout endpoints are exempt
        so the user can actually set a new password (or bail out).
        """
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get("user"):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Authentication required"}), 401
                return redirect(url_for("login", next=request.path))

            if session.get("must_change"):
                # Block everything except the change-password page itself
                # and the logout escape hatch.
                exempt = {"change_password", "change_password_post", "logout"}
                if request.endpoint not in exempt:
                    if request.path.startswith("/api/"):
                        return jsonify({
                            "error": "Password change required",
                            "redirect": url_for("change_password"),
                        }), 403
                    return redirect(url_for("change_password"))
            return fn(*args, **kwargs)
        return wrapper

    # --------------------------------------------------------------- auth routes

    @app.get("/login")
    def login():
        if session.get("user"):
            # Already logged in — but if they're flagged must_change,
            # send them straight to the change-password page.
            if session.get("must_change"):
                return redirect(url_for("change_password"))
            return redirect(url_for("dashboard"))
        return render_template(
            "login.html",
            radius_configured=radius.is_configured(),
            local_auth_enabled=local_auth_enabled,
            errors=get_flashed_messages(category_filter=["error"]),
            next_url=request.args.get("next", ""),
        )

    @app.post("/login")
    def login_post():
        """
        Authentication order: local first (covers the bootstrap admin
        and any manually-added local accounts), then RADIUS if enabled.
        Local first means RADIUS outages don't lock the operator out.
        """
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        next_url = request.form.get("next", "") or url_for("dashboard")

        # Only redirect to internal paths — blocks open-redirect attacks.
        if not next_url.startswith("/") or next_url.startswith("//"):
            next_url = url_for("dashboard")

        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for("login", next=next_url))

        if not local_auth_enabled and not radius.is_configured():
            log.warning("Login attempt rejected — no auth backend configured (user=%s)",
                        username)
            flash("Authentication service is not configured. Contact your administrator.",
                  "error")
            return redirect(url_for("login", next=next_url))

        # Local first
        auth_method:    Optional[str]  = None
        must_change:    bool           = False
        if local_auth_enabled and local_store.authenticate(username, password):
            auth_method = "local"
            must_change = local_store.must_change_password(username)

        # RADIUS fallback
        elif radius.is_configured() and radius.authenticate(username, password):
            auth_method = "radius"

        if auth_method is None:
            log.info("Web UI: failed login attempt user=%s from %s",
                     username, request.remote_addr)
            flash("Invalid username or password.", "error")
            return redirect(url_for("login", next=next_url))

        session.clear()
        session["user"]        = username
        session["auth_method"] = auth_method
        session["must_change"] = must_change
        session.permanent      = True
        log.info("Web UI: user=%s logged in via %s from %s",
                 username, auth_method, request.remote_addr)

        if must_change:
            flash("You're using a default password. Please set a new one.", "warning")
            return redirect(url_for("change_password"))
        return redirect(next_url)

    @app.get("/logout")
    def logout():
        user = session.get("user")
        session.clear()
        if user:
            log.info("Web UI: user=%s logged out", user)
        return redirect(url_for("login"))

    # ------------------------------------------------------- forced password change

    @app.get("/change-password")
    @require_login
    def change_password():
        return render_template(
            "change_password.html",
            current_user = session.get("user"),
            auth_method  = session.get("auth_method"),
            must_change  = bool(session.get("must_change")),
            errors       = get_flashed_messages(category_filter=["error"]),
            messages     = get_flashed_messages(category_filter=["success"]),
        )

    @app.post("/change-password")
    @require_login
    def change_password_post():
        """
        Update a local user's password. RADIUS users can't change their
        password here — that's owned by the RADIUS server.
        """
        if session.get("auth_method") != "local":
            flash("Password changes for RADIUS users must be made on the RADIUS server.",
                  "error")
            return redirect(url_for("dashboard"))

        username = session.get("user", "")
        current  = request.form.get("current_password") or ""
        new_pw   = request.form.get("new_password") or ""
        confirm  = request.form.get("confirm_password") or ""

        if not local_store.authenticate(username, current):
            flash("Current password is incorrect.", "error")
            return redirect(url_for("change_password"))
        if new_pw != confirm:
            flash("New passwords do not match.", "error")
            return redirect(url_for("change_password"))
        if len(new_pw) < 8:
            flash("New password must be at least 8 characters.", "error")
            return redirect(url_for("change_password"))
        if new_pw == current:
            flash("New password must be different from the current one.", "error")
            return redirect(url_for("change_password"))

        if not local_store.change_password(username, new_pw):
            flash("Could not update password.", "error")
            return redirect(url_for("change_password"))

        # Lift the must_change session flag now that they've complied.
        session["must_change"] = False
        flash("Password updated.", "success")
        return redirect(url_for("dashboard"))

    # ----------------------------------------------------------------- settings

    @app.get("/settings")
    @require_login
    def settings_page():
        """
        Settings shell. Phase B will add per-section editors for the
        full config.ini surface. For now this is a placeholder that
        confirms the route + sprocket icon are wired up correctly.
        """
        return render_template(
            "settings.html",
            current_user = session.get("user"),
            auth_method  = session.get("auth_method"),
        )

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
