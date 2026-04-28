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
import smtplib
import subprocess
import threading
from datetime import timedelta
from email.message import EmailMessage
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

from aruba_agent.auth          import RadiusAuthenticator
from aruba_agent.config_editor import ConfigEditor
from aruba_agent.local_auth    import LocalAuthStore
from aruba_agent.state         import AgentState

log = logging.getLogger(__name__)


def create_app(
    state: AgentState,
    backup_fn:   Optional[Callable] = None,
    scanner_fn:  Optional[Callable] = None,
    cfg: Optional[configparser.ConfigParser] = None,
    cfg_path: Optional[str] = None,
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

    # ConfigEditor — only available when main.py passed us a cfg_path.
    # In firmware-update mode or other CLI paths there is no path to
    # write back to, so settings editing is disabled.
    editor: Optional[ConfigEditor] = ConfigEditor(cfg_path) if cfg_path else None
    if editor is not None:
        log.info("Web UI: settings editor active (config=%s, writable=%s)",
                 cfg_path, editor.writable())

    # Restart-now capability detection. Requires a sudoers rule:
    #     aruba-agent ALL=(root) NOPASSWD: /bin/systemctl restart aruba-agent
    # If the rule is missing the UI hides the Restart Now button and
    # shows the manual command instead.
    def _can_restart_via_sudo() -> bool:
        try:
            r = subprocess.run(
                ["sudo", "-n", "-l", "/bin/systemctl", "restart", "aruba-agent"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            return r.returncode == 0
        except (FileNotFoundError, subprocess.SubprocessError):
            return False

    can_restart = _can_restart_via_sudo()
    log.info("Web UI: restart-via-sudo %s",
             "available" if can_restart else "NOT available — manual restart only")

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

    def _settings_context() -> dict:
        """Common context every settings page needs."""
        return {
            "current_user": session.get("user"),
            "auth_method":  session.get("auth_method"),
            "editor_writable": (editor is not None) and editor.writable(),
            "config_path":  cfg_path,
            "can_restart":  can_restart,
        }

    @app.get("/settings")
    @require_login
    def settings_page():
        return render_template("settings.html", **_settings_context())

    # ── Restart now ─────────────────────────────────────────────────────────

    @app.post("/api/settings/restart")
    @require_login
    def settings_restart():
        """
        Trigger a service restart via sudoers-allowed systemctl.
        Detached so the HTTP response can flush before systemd kills
        this process. The browser polls /api/state until it comes
        back, then reloads.
        """
        if not can_restart:
            return jsonify({
                "error": "Restart-now is not configured. Run manually: "
                         "sudo systemctl restart aruba-agent",
            }), 503
        log.info("Web UI: restart triggered by user=%s", session.get("user"))
        # bash -c so we can chain sleep + systemctl in a detached subshell
        subprocess.Popen(
            ["bash", "-c",
             "sleep 1 && sudo -n /bin/systemctl restart aruba-agent"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return jsonify({"status": "restarting", "wait_seconds": 6})

    # ── Authentication editor (RADIUS + local user list) ───────────────────

    @app.get("/settings/auth")
    @require_login
    def settings_auth():
        if editor is None:
            abort(404)
        live = editor.read()
        radius_cfg = live["radius"] if live.has_section("radius") else {}
        local_cfg  = live["local_auth"] if live.has_section("local_auth") else {}
        users      = local_store.list_users()

        ctx = _settings_context()
        ctx.update({
            "users":              users,
            "local_enabled":      local_cfg.get("enabled", "true").lower() == "true",
            "local_store_file":   local_cfg.get("store_file",
                                                "/var/lib/aruba-agent/users.json"),
            "radius_enabled":     radius_cfg.get("enabled", "false").lower() == "true",
            "radius_server":      radius_cfg.get("server", ""),
            "radius_port":        radius_cfg.get("port", "1812"),
            "radius_nas":         radius_cfg.get("nas_identifier",
                                                 "aruba-switch-manager"),
            "radius_timeout":     radius_cfg.get("timeout", "5"),
            "radius_retries":     radius_cfg.get("retries", "2"),
            "radius_secret_set":  bool(radius_cfg.get("secret", "").strip()),
            "errors":             get_flashed_messages(category_filter=["error"]),
            "messages":           get_flashed_messages(category_filter=["success"]),
        })
        return render_template("settings_auth.html", **ctx)

    @app.post("/settings/auth")
    @require_login
    def settings_auth_post():
        if editor is None or not editor.writable():
            flash("Config file is not writable by the agent. Fix permissions and retry.",
                  "error")
            return redirect(url_for("settings_auth"))

        form = request.form

        # Local-auth section
        local_values = {
            "enabled":    "true" if form.get("local_enabled") == "on" else "false",
            "store_file": (form.get("local_store_file") or
                           "/var/lib/aruba-agent/users.json").strip(),
        }

        # RADIUS section. The shared secret is special: we keep the
        # existing value if the form field was left blank.
        radius_values = {
            "enabled":         "true" if form.get("radius_enabled") == "on" else "false",
            "server":          (form.get("radius_server") or "").strip(),
            "port":            (form.get("radius_port") or "1812").strip(),
            "nas_identifier":  (form.get("radius_nas") or "aruba-switch-manager").strip(),
            "timeout":         (form.get("radius_timeout") or "5").strip(),
            "retries":         (form.get("radius_retries") or "2").strip(),
        }
        new_secret = form.get("radius_secret") or ""
        live = editor.read()
        if new_secret.strip():
            radius_values["secret"] = new_secret
        else:
            # Preserve the existing on-disk secret untouched
            existing = live["radius"]["secret"] if (
                live.has_section("radius") and live.has_option("radius", "secret")
            ) else ""
            radius_values["secret"] = existing

        # Validation
        if radius_values["enabled"] == "true":
            if not radius_values["server"]:
                flash("RADIUS server is required when RADIUS is enabled.", "error")
                return redirect(url_for("settings_auth"))
            if not radius_values["secret"]:
                flash("RADIUS shared secret is required when RADIUS is enabled.", "error")
                return redirect(url_for("settings_auth"))
        if local_values["enabled"] != "true" and radius_values["enabled"] != "true":
            flash("At least one auth backend (Local or RADIUS) must be enabled — "
                  "otherwise no one can sign in.", "error")
            return redirect(url_for("settings_auth"))

        editor.update_section("local_auth", local_values)
        editor.update_section("radius",     radius_values)
        log.info("Web UI: auth settings updated by user=%s", session.get("user"))
        flash("Authentication settings saved. Restart the agent to apply.", "success")
        return redirect(url_for("settings_auth"))

    @app.post("/settings/auth/users/add")
    @require_login
    def settings_user_add():
        username = (request.form.get("new_username") or "").strip()
        password = request.form.get("new_password") or ""
        if not username or not password:
            flash("Username and password are required.", "error")
        elif len(password) < LocalAuthStore.MIN_PASSWORD_LEN:
            flash(f"Password must be at least {LocalAuthStore.MIN_PASSWORD_LEN} "
                  "characters.", "error")
        elif not local_store.add_user(username, password):
            flash(f"Could not add user '{username}' (name may already exist).",
                  "error")
        else:
            log.info("Web UI: local user added: %s (by %s)",
                     username, session.get("user"))
            flash(f"User '{username}' added.", "success")
        return redirect(url_for("settings_auth"))

    @app.post("/settings/auth/users/<username>/remove")
    @require_login
    def settings_user_remove(username: str):
        # Refuse to remove the user you're currently signed in as
        if username == session.get("user"):
            flash("You can't remove the user you're signed in as.", "error")
            return redirect(url_for("settings_auth"))
        if not local_store.remove_user(username):
            flash(f"Could not remove '{username}' (not found, or it's the last user).",
                  "error")
        else:
            log.info("Web UI: local user removed: %s (by %s)",
                     username, session.get("user"))
            flash(f"User '{username}' removed.", "success")
        return redirect(url_for("settings_auth"))

    # ── Email alerts editor (SMTP + test send) ─────────────────────────────

    @app.get("/settings/email")
    @require_login
    def settings_email():
        if editor is None:
            abort(404)
        live = editor.read()
        smtp_cfg = live["smtp"] if live.has_section("smtp") else {}

        ctx = _settings_context()
        ctx.update({
            "smtp_enabled":   smtp_cfg.get("enabled",  "false").lower() == "true",
            "smtp_host":      smtp_cfg.get("host",     ""),
            "smtp_port":      smtp_cfg.get("port",     "587"),
            "smtp_use_tls":   smtp_cfg.get("use_tls",  "true").lower() == "true",
            "smtp_username":  smtp_cfg.get("username", ""),
            "smtp_from":      smtp_cfg.get("from",     ""),
            "smtp_to":        smtp_cfg.get("to",       ""),
            "smtp_password_set": bool(smtp_cfg.get("password", "").strip()),
            "errors":         get_flashed_messages(category_filter=["error"]),
            "messages":       get_flashed_messages(category_filter=["success"]),
        })
        return render_template("settings_email.html", **ctx)

    @app.post("/settings/email")
    @require_login
    def settings_email_post():
        if editor is None or not editor.writable():
            flash("Config file is not writable by the agent. Fix permissions and retry.",
                  "error")
            return redirect(url_for("settings_email"))

        form = request.form
        live = editor.read()

        values = {
            "enabled":  "true" if form.get("smtp_enabled") == "on" else "false",
            "host":     (form.get("smtp_host")     or "").strip(),
            "port":     (form.get("smtp_port")     or "587").strip(),
            "use_tls":  "true" if form.get("smtp_use_tls") == "on" else "false",
            "username": (form.get("smtp_username") or "").strip(),
            "from":     (form.get("smtp_from")     or "").strip(),
            "to":       (form.get("smtp_to")       or "").strip(),
        }
        new_pw = form.get("smtp_password") or ""
        if new_pw:
            values["password"] = new_pw
        elif live.has_section("smtp") and live.has_option("smtp", "password"):
            values["password"] = live["smtp"]["password"]
        else:
            values["password"] = ""

        if values["enabled"] == "true" and not values["host"]:
            flash("SMTP host is required when email alerts are enabled.", "error")
            return redirect(url_for("settings_email"))

        editor.update_section("smtp", values)
        log.info("Web UI: SMTP settings updated by user=%s", session.get("user"))
        flash("Email settings saved. Restart the agent to apply.", "success")
        return redirect(url_for("settings_email"))

    @app.post("/api/settings/email/test")
    @require_login
    def settings_email_test():
        """
        Send a one-shot test email using the values currently on disk
        in /etc/aruba-agent/config.ini. Doesn't depend on the running
        agent's notifier — operator can confirm SMTP works before
        restarting.
        """
        if editor is None:
            return jsonify({"error": "settings editor disabled"}), 503
        live = editor.read()
        if not live.has_section("smtp"):
            return jsonify({"error": "[smtp] section is missing — save it first"}), 400
        s = live["smtp"]

        host    = (s.get("host", "") or "").strip()
        port    = int(s.get("port", "587") or "587")
        use_tls = s.get("use_tls", "true").lower() == "true"
        user    = (s.get("username", "") or "").strip()
        pw      = s.get("password", "") or ""
        sender  = (s.get("from", "") or user).strip() or "aruba-agent"
        to_str  = (s.get("to", "") or "").strip()
        recipients = [r.strip() for r in to_str.split(",") if r.strip()]

        if not host or not recipients:
            return jsonify({"error": "host and at least one recipient required"}), 400

        msg = EmailMessage()
        msg["Subject"] = "[Aruba] SMTP test message"
        msg["From"]    = sender
        msg["To"]      = ", ".join(recipients)
        msg.set_content(
            "This is a test message sent from the Aruba Network Agent "
            "Settings page.\n\nIf you received it, your SMTP configuration "
            "is working.\n"
        )

        try:
            with smtplib.SMTP(host, port, timeout=10) as smtp:
                if use_tls:
                    smtp.starttls()
                if user and pw:
                    smtp.login(user, pw)
                smtp.send_message(msg, from_addr=sender, to_addrs=recipients)
            log.info("Web UI: SMTP test send succeeded (recipients=%s, by %s)",
                     recipients, session.get("user"))
            return jsonify({"status": "sent", "recipients": recipients})
        except (smtplib.SMTPException, OSError) as exc:
            log.warning("Web UI: SMTP test send failed: %s", exc)
            return jsonify({"error": str(exc)}), 502

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
