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
import ipaddress
import logging
import os
import re
import secrets
import smtplib
import subprocess
import threading
from datetime import timedelta
from email.message import EmailMessage
from typing import Callable, List, Optional, Tuple

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
    arp_fns:     Optional[dict]     = None,   # {location_name: callable}
    cfg: Optional[configparser.ConfigParser] = None,
    cfg_path: Optional[str] = None,
    snmp_agent = None,    # Optional[SnmpAgent] — duck-typed via .registry
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

    # ── Validation helpers (shared by Phase B2 editors) ────────────────────

    _HHMM = re.compile(r"^\s*(\d{1,2}):(\d{2})\s*$")
    _LOCATION_NAME = re.compile(r"^[a-zA-Z0-9._-]+$")

    def _csv(s: str) -> List[str]:
        return [x.strip() for x in (s or "").split(",") if x.strip()]

    def _validate_hhmm(s: str) -> Optional[str]:
        m = _HHMM.match(s or "")
        if not m:
            return None
        h, mn = int(m.group(1)), int(m.group(2))
        if not (0 <= h <= 23 and 0 <= mn <= 59):
            return None
        return f"{h:02d}:{mn:02d}"

    def _validate_cidrs(s: str) -> Tuple[bool, List[str]]:
        """Returns (ok, list-of-bad-entries). Empty input is ok."""
        bad: List[str] = []
        for item in _csv(s):
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                bad.append(item)
        return (not bad, bad)

    def _validate_ips(s: str) -> Tuple[bool, List[str]]:
        bad: List[str] = []
        for item in _csv(s):
            try:
                ipaddress.ip_address(item)
            except ValueError:
                bad.append(item)
        return (not bad, bad)

    def _editor_required():
        """Return a redirect+flash if config can't be saved; else None."""
        if editor is None:
            flash("Settings editor disabled (no config path).", "error")
            return redirect(url_for("settings_page"))
        if not editor.writable():
            flash("Config file is not writable by the agent. "
                  "Fix permissions and retry.", "error")
            return redirect(url_for("settings_page"))
        return None

    # ── SNMPv3 — multi-profile management (C6.4) ──────────────────────────

    _PROFILE_NAME = re.compile(r"^[a-zA-Z0-9_-]+$")

    def _list_profiles_from_disk(live: configparser.ConfigParser):
        """Find every [snmp.<name>] section in the live config and
        return a summary list ordered by name. The summary intentionally
        omits passwords — the per-profile editor reads them on demand."""
        out = []
        for section in live.sections():
            if not section.startswith("snmp.") or section == "snmp.":
                continue
            name = section[len("snmp."):]
            p = live[section]
            out.append({
                "name":          name,
                "username":      p.get("username", "") or "",
                "auth_protocol": p.get("auth_protocol", "SHA"),
                "priv_protocol": p.get("priv_protocol", "AES128"),
                "context_name":  p.get("context_name", "") or "",
                "auth_set":      bool((p.get("auth_password", "") or "").strip()),
                "priv_set":      bool((p.get("priv_password", "") or "").strip()),
            })
        return sorted(out, key=lambda x: x["name"])

    @app.get("/settings/snmp")
    @require_login
    def settings_snmp():
        if editor is None:
            abort(404)
        live = editor.read()
        s = live["snmp"] if live.has_section("snmp") else {}
        profiles = _list_profiles_from_disk(live)

        # Detect legacy single-profile config: [snmp] has credential
        # keys but no [snmp.<name>] sections exist. We surface this in
        # the UI so the operator can migrate explicitly.
        legacy_creds_present = any(
            k in s for k in
            ("username", "auth_password", "priv_password", "context_name")
        ) and not profiles

        ctx = _settings_context()
        ctx.update({
            "enabled":              s.get("enabled", "false").lower() == "true",
            "default_profile":      s.get("default_profile", "default"),
            "profiles":             profiles,
            "legacy_creds_present": legacy_creds_present,
            "errors":               get_flashed_messages(category_filter=["error"]),
            "messages":             get_flashed_messages(category_filter=["success"]),
        })
        return render_template("settings_snmp.html", **ctx)

    @app.post("/settings/snmp")
    @require_login
    def settings_snmp_post():
        """Save the global [snmp] keys: enabled + default_profile.
        Per-profile credentials are saved through the per-profile editor."""
        guard = _editor_required()
        if guard is not None: return guard

        f = request.form
        default_profile = (f.get("default_profile") or "").strip()

        # If a default_profile was named, validate it exists on disk.
        if default_profile:
            live = editor.read()
            if not live.has_section(f"snmp.{default_profile}"):
                flash(f"Default profile {default_profile!r} doesn't exist. "
                      "Add it first, then come back to save.", "error")
                return redirect(url_for("settings_snmp"))

        editor.update_section("snmp", {
            "enabled":         "true" if f.get("enabled") == "on" else "false",
            "default_profile": default_profile,
        })
        log.info("Web UI: SNMP global settings updated by user=%s",
                 session.get("user"))
        flash("SNMP global settings saved. Restart the agent to apply.",
              "success")
        return redirect(url_for("settings_snmp"))

    # ── Per-profile editor ────────────────────────────────────────────────

    @app.get("/settings/snmp/profile/<name>")
    @require_login
    def settings_snmp_profile(name: str):
        if editor is None:
            abort(404)
        if not _PROFILE_NAME.match(name):
            abort(400)
        live = editor.read()
        section = f"snmp.{name}"
        if not live.has_section(section):
            flash(f"SNMP profile {name!r} not found.", "error")
            return redirect(url_for("settings_snmp"))
        p = live[section]
        ctx = _settings_context()
        ctx.update({
            "name":              name,
            "username":          p.get("username", ""),
            "context_name":      p.get("context_name", ""),
            "context_engine_id": p.get("context_engine_id", ""),
            "auth_protocol":     p.get("auth_protocol", "SHA"),
            "priv_protocol":     p.get("priv_protocol", "AES128"),
            "port":              p.get("port", "161"),
            "timeout":           p.get("timeout", "2"),
            "retries":           p.get("retries", "1"),
            "auth_password_set": bool((p.get("auth_password", "") or "").strip()),
            "priv_password_set": bool((p.get("priv_password", "") or "").strip()),
            "errors":            get_flashed_messages(category_filter=["error"]),
            "messages":          get_flashed_messages(category_filter=["success"]),
        })
        return render_template("settings_snmp_profile.html", **ctx)

    @app.post("/settings/snmp/profile/<name>")
    @require_login
    def settings_snmp_profile_post(name: str):
        guard = _editor_required()
        if guard is not None: return guard
        if not _PROFILE_NAME.match(name):
            abort(400)

        section = f"snmp.{name}"
        f = request.form

        try:
            port    = int(f.get("port")    or "161")
            timeout = int(f.get("timeout") or "2")
            retries = int(f.get("retries") or "1")
            if not (1 <= port <= 65535) or timeout < 1 or retries < 0:
                raise ValueError
        except ValueError:
            flash("Port (1-65535), timeout (≥1), retries (≥0) must be valid "
                  "integers.", "error")
            return redirect(url_for("settings_snmp_profile", name=name))

        live = editor.read()
        existing_auth = (live[section]["auth_password"]
                         if live.has_section(section) and
                            live.has_option(section, "auth_password") else "")
        existing_priv = (live[section]["priv_password"]
                         if live.has_section(section) and
                            live.has_option(section, "priv_password") else "")
        new_auth = f.get("auth_password") or ""
        new_priv = f.get("priv_password") or ""

        cei = (f.get("context_engine_id") or "").strip().replace(":", "")
        if cei:
            if not re.fullmatch(r"[0-9a-fA-F]+", cei) or len(cei) % 2:
                flash("Context engine ID must be an even-length hex string.",
                      "error")
                return redirect(url_for("settings_snmp_profile", name=name))

        values = {
            "username":          (f.get("username") or "").strip(),
            "context_name":      (f.get("context_name") or "").strip(),
            "context_engine_id": cei,
            "auth_protocol":     (f.get("auth_protocol") or "SHA").strip().upper(),
            "auth_password":     new_auth if new_auth else existing_auth,
            "priv_protocol":     (f.get("priv_protocol") or "AES128").strip().upper(),
            "priv_password":     new_priv if new_priv else existing_priv,
            "port":              str(port),
            "timeout":           str(timeout),
            "retries":           str(retries),
        }
        if not values["username"]:
            flash("Username is required for an SNMPv3 profile.", "error")
            return redirect(url_for("settings_snmp_profile", name=name))

        editor.update_section(section, values)
        log.info("Web UI: SNMP profile %r saved by user=%s",
                 name, session.get("user"))
        flash(f"Profile {name!r} saved. Restart the agent to apply.",
              "success")
        return redirect(url_for("settings_snmp_profile", name=name))

    # ── Add a new profile ─────────────────────────────────────────────────

    @app.post("/settings/snmp/profile/add")
    @require_login
    def settings_snmp_profile_add():
        guard = _editor_required()
        if guard is not None: return guard

        name = (request.form.get("name") or "").strip()
        if not name or not _PROFILE_NAME.match(name):
            flash("Profile name must be alphanumeric (plus _ and -). "
                  "Try 'aruba', 'cisco', etc.", "error")
            return redirect(url_for("settings_snmp"))

        live = editor.read()
        section = f"snmp.{name}"
        if live.has_section(section):
            flash(f"Profile {name!r} already exists.", "error")
            return redirect(url_for("settings_snmp"))

        editor.update_section(section, {
            "username":          "",
            "context_name":      "",
            "context_engine_id": "",
            "auth_protocol":     "SHA",
            "auth_password":     "",
            "priv_protocol":     "AES128",
            "priv_password":     "",
            "port":              "161",
            "timeout":           "2",
            "retries":           "1",
        })
        log.info("Web UI: SNMP profile %r created by user=%s",
                 name, session.get("user"))
        flash(f"Profile {name!r} created. Fill in credentials and save.",
              "success")
        return redirect(url_for("settings_snmp_profile", name=name))

    # ── Remove a profile ──────────────────────────────────────────────────

    @app.post("/settings/snmp/profile/<name>/remove")
    @require_login
    def settings_snmp_profile_remove(name: str):
        guard = _editor_required()
        if guard is not None: return guard
        if not _PROFILE_NAME.match(name):
            abort(400)

        live   = editor.read()
        header = editor.read_header()
        section = f"snmp.{name}"
        if not live.has_section(section):
            flash(f"Profile {name!r} doesn't exist.", "error")
            return redirect(url_for("settings_snmp"))

        # Don't let the operator delete the profile listed as
        # default_profile — they'd be left with no fallback. Make
        # them flip default_profile first.
        if (live.has_section("snmp") and
                live.has_option("snmp", "default_profile") and
                live["snmp"]["default_profile"].strip() == name):
            flash(f"Profile {name!r} is set as the default. Change "
                  "default_profile first, then come back to remove this.",
                  "error")
            return redirect(url_for("settings_snmp"))

        live.remove_section(section)
        editor.save(live, header=header)
        log.info("Web UI: SNMP profile %r removed by user=%s",
                 name, session.get("user"))
        flash(f"Profile {name!r} removed. Restart the agent to apply.",
              "success")
        return redirect(url_for("settings_snmp"))

    @app.post("/api/settings/snmp/test")
    @require_login
    def settings_snmp_test():
        """Send a single sysUpTime.0 GET to a target host using one of
        the on-disk SNMP profiles. Operator can validate credentials
        per-profile before restarting the agent.

        Query string:
            host    — required, target switch IP
            profile — optional profile name; defaults to the
                      registry's configured default."""
        if editor is None:
            return jsonify({"error": "settings editor disabled"}), 503
        target  = (request.args.get("host") or "").strip()
        profile = (request.args.get("profile") or "").strip() or None
        if not target:
            return jsonify({"error": "host query parameter is required"}), 400

        from aruba_agent.snmp import from_config as build_snmp
        live = editor.read()
        agent = build_snmp(live)
        if agent is None:
            return jsonify({"error":
                "SNMP is not enabled or no profile is configured. "
                "Add at least one profile under [snmp.<name>]."}), 400

        if profile and profile not in agent.registry:
            return jsonify({"error":
                f"Unknown profile {profile!r}. "
                f"Available: {agent.registry.names()}"}), 400

        # Surface the specific failure mode so the UI can show a
        # useful hint instead of "no response, ¯\_(ツ)_/¯".
        hints = {
            "pysnmp_not_installed":
                "Install pysnmp on the agent host: "
                "sudo pip3 install -r /opt/aruba-agent/requirements.txt",
            "pysnmp_incompatible_version":
                "pysnmp 6.2+ removed the synchronous API the agent needs. "
                "Downgrade with: "
                "sudo pip3 uninstall -y pysnmp && sudo pip3 install 'pysnmp<6.2' "
                "&& sudo systemctl restart aruba-agent",
            "timeout":
                f"No reply from {target}. Check L3 reachability, "
                "the switch's management ACL, and that UDP/161 is "
                "open from the agent host.",
            "auth_failure":
                "Authentication digest mismatch. The auth password or "
                "auth protocol on the agent doesn't match the switch.",
            "engine_id_mismatch":
                "Context engine ID mismatch. Try clearing the "
                "Context engine ID field so pysnmp auto-discovers it.",
            "unknown_user":
                "The switch doesn't have an SNMPv3 user with that name. "
                "Check the User (Security Name) field.",
            "privacy_failure":
                "Privacy decryption failed. The priv password or priv "
                "protocol on the agent doesn't match the switch.",
            "bad_context_engine_id":
                "Context engine ID is not valid hex. Use even-length "
                "hex characters only, no separators.",
        }

        uptime = agent.get_uptime_centiseconds(target, profile_name=profile)
        if uptime is None:
            err_code = agent.last_error or "unknown"
            return jsonify({
                "error":   hints.get(err_code,
                                     f"SNMP request failed ({err_code})."),
                "code":    err_code,
                "detail":  agent.last_detail,
                "profile": profile or agent.registry.default_name,
            }), 502

        sys_name  = agent.get_sys_name (target, profile_name=profile)
        sys_descr = agent.get_sys_descr(target, profile_name=profile)
        return jsonify({
            "status":              "ok",
            "host":                target,
            "profile":             profile or agent.registry.default_name,
            "uptime_centiseconds": uptime,
            "sys_name":            sys_name,
            "sys_descr":           sys_descr,
        })

    # ── Switch credentials ────────────────────────────────────────────────

    @app.get("/settings/credentials")
    @require_login
    def settings_credentials():
        if editor is None:
            abort(404)
        live = editor.read()
        c = live["credentials"] if live.has_section("credentials") else {}
        ctx = _settings_context()
        ctx.update({
            "username":      c.get("username", ""),
            "password_set":  bool(c.get("password", "").strip()),
            "errors":        get_flashed_messages(category_filter=["error"]),
            "messages":      get_flashed_messages(category_filter=["success"]),
        })
        return render_template("settings_credentials.html", **ctx)

    @app.post("/settings/credentials")
    @require_login
    def settings_credentials_post():
        guard = _editor_required()
        if guard is not None: return guard

        username = (request.form.get("username") or "").strip()
        new_pw   = request.form.get("password") or ""
        if not username:
            flash("Username is required.", "error")
            return redirect(url_for("settings_credentials"))

        live = editor.read()
        existing = (live["credentials"]["password"]
                    if live.has_section("credentials") and
                       live.has_option("credentials", "password")
                    else "")
        editor.update_section("credentials", {
            "username": username,
            "password": new_pw if new_pw else existing,
        })
        log.info("Web UI: switch credentials updated by user=%s",
                 session.get("user"))
        flash("Switch credentials saved. Restart the agent to apply.", "success")
        return redirect(url_for("settings_credentials"))

    # ── Cisco IOS / IOS-XE credentials ────────────────────────────────────

    _NAPALM_CISCO_DRIVERS = ("ios", "iosxr", "nxos_ssh")

    @app.get("/settings/credentials/cisco")
    @require_login
    def settings_cisco_credentials():
        if editor is None:
            abort(404)
        live = editor.read()
        c = live["credentials.cisco"] if live.has_section("credentials.cisco") else {}
        ctx = _settings_context()
        ctx.update({
            "username":            c.get("username", ""),
            "password_set":        bool(c.get("password", "").strip()),
            "enable_secret_set":   bool(c.get("enable_secret", "").strip()),
            "napalm_driver":       c.get("napalm_driver", "ios"),
            "napalm_drivers":      _NAPALM_CISCO_DRIVERS,
            "errors":              get_flashed_messages(category_filter=["error"]),
            "messages":            get_flashed_messages(category_filter=["success"]),
        })
        return render_template("settings_cisco_credentials.html", **ctx)

    @app.post("/settings/credentials/cisco")
    @require_login
    def settings_cisco_credentials_post():
        guard = _editor_required()
        if guard is not None: return guard

        f = request.form
        username    = (f.get("username") or "").strip()
        new_pw      = f.get("password") or ""
        new_enable  = f.get("enable_secret") or ""
        nap_driver  = (f.get("napalm_driver") or "ios").strip()

        if nap_driver not in _NAPALM_CISCO_DRIVERS:
            flash(f"Unknown NAPALM driver {nap_driver!r}. Pick one of "
                  f"{', '.join(_NAPALM_CISCO_DRIVERS)}.", "error")
            return redirect(url_for("settings_cisco_credentials"))

        live = editor.read()
        existing_pw = (live["credentials.cisco"]["password"]
                       if live.has_section("credentials.cisco") and
                          live.has_option("credentials.cisco", "password")
                       else "")
        existing_enable = (live["credentials.cisco"]["enable_secret"]
                           if live.has_section("credentials.cisco") and
                              live.has_option("credentials.cisco", "enable_secret")
                           else "")

        editor.update_section("credentials.cisco", {
            "username":      username,
            "password":      new_pw     if new_pw     else existing_pw,
            "enable_secret": new_enable if new_enable else existing_enable,
            "napalm_driver": nap_driver,
        })
        log.info("Web UI: Cisco credentials updated by user=%s",
                 session.get("user"))
        flash("Cisco credentials saved. Restart the agent to apply.", "success")
        return redirect(url_for("settings_cisco_credentials"))

    # ── Arista EOS credentials ────────────────────────────────────────────

    _ARISTA_TRANSPORTS = ("https", "http")

    @app.get("/settings/credentials/arista")
    @require_login
    def settings_arista_credentials():
        if editor is None:
            abort(404)
        live = editor.read()
        a = live["credentials.arista"] if live.has_section("credentials.arista") else {}
        ctx = _settings_context()
        ctx.update({
            "username":               a.get("username", ""),
            "password_set":           bool(a.get("password", "").strip()),
            "enable_password_set":    bool(a.get("enable_password", "").strip()),
            "transport":              a.get("transport", "https"),
            "transports":             _ARISTA_TRANSPORTS,
            "port":                   a.get("port", ""),
            "errors":                 get_flashed_messages(category_filter=["error"]),
            "messages":               get_flashed_messages(category_filter=["success"]),
        })
        return render_template("settings_arista_credentials.html", **ctx)

    @app.post("/settings/credentials/arista")
    @require_login
    def settings_arista_credentials_post():
        guard = _editor_required()
        if guard is not None: return guard

        f = request.form
        username   = (f.get("username") or "").strip()
        new_pw     = f.get("password") or ""
        new_enable = f.get("enable_password") or ""
        transport  = (f.get("transport") or "https").strip().lower()
        port_raw   = (f.get("port") or "").strip()

        if transport not in _ARISTA_TRANSPORTS:
            flash(f"Transport must be one of {', '.join(_ARISTA_TRANSPORTS)}.",
                  "error")
            return redirect(url_for("settings_arista_credentials"))

        if port_raw:
            try:
                port = int(port_raw)
                if not (1 <= port <= 65535):
                    raise ValueError
            except ValueError:
                flash("Port must be an integer 1-65535 (or blank for "
                      "NAPALM default).", "error")
                return redirect(url_for("settings_arista_credentials"))
        else:
            port = ""

        live = editor.read()
        existing_pw = (live["credentials.arista"]["password"]
                       if live.has_section("credentials.arista") and
                          live.has_option("credentials.arista", "password")
                       else "")
        existing_enable = (live["credentials.arista"]["enable_password"]
                           if live.has_section("credentials.arista") and
                              live.has_option("credentials.arista", "enable_password")
                           else "")

        editor.update_section("credentials.arista", {
            "username":        username,
            "password":        new_pw     if new_pw     else existing_pw,
            "enable_password": new_enable if new_enable else existing_enable,
            "transport":       transport,
            "port":            str(port) if port != "" else "",
        })
        log.info("Web UI: Arista credentials updated by user=%s",
                 session.get("user"))
        flash("Arista credentials saved. Restart the agent to apply.", "success")
        return redirect(url_for("settings_arista_credentials"))

    # ── Network scanner ───────────────────────────────────────────────────

    @app.get("/settings/scanner")
    @require_login
    def settings_scanner():
        if editor is None:
            abort(404)
        live = editor.read()
        s = live["scanner"] if live.has_section("scanner") else {}
        ctx = _settings_context()
        ctx.update({
            "enabled":          s.get("enabled",          "true").lower() == "true",
            "schedule":         s.get("schedule",         "00:00"),
            "subnets":          s.get("subnets",          ""),
            "exclude_suffixes": s.get("exclude_suffixes", "1,2,3,255"),
            "filter_keywords":  s.get("filter_keywords",  "6100,6300,Aruba"),
            "device_file":      s.get("device_file",
                                      "/var/lib/aruba-agent/network_devices.csv"),
            "ip_list_output":   s.get("ip_list_output",
                                      "/var/lib/aruba-agent/ip_list.txt"),
            "icmp_timeout":     s.get("icmp_timeout",     "8"),
            "verify_via_api":   s.get("verify_via_api",   "true").lower() == "true",
            "api_workers":      s.get("api_workers",      "16"),
            "errors":           get_flashed_messages(category_filter=["error"]),
            "messages":         get_flashed_messages(category_filter=["success"]),
        })
        return render_template("settings_scanner.html", **ctx)

    @app.post("/settings/scanner")
    @require_login
    def settings_scanner_post():
        guard = _editor_required()
        if guard is not None: return guard

        f = request.form
        sched = _validate_hhmm(f.get("schedule") or "")
        if sched is None:
            flash("Schedule must be HH:MM (24-hour).", "error")
            return redirect(url_for("settings_scanner"))

        ok, bad = _validate_cidrs(f.get("subnets") or "")
        if not ok:
            flash(f"Invalid subnet(s): {', '.join(bad)}", "error")
            return redirect(url_for("settings_scanner"))

        try:
            timeout = int(f.get("icmp_timeout") or "8")
            workers = int(f.get("api_workers")  or "16")
            if timeout < 1 or workers < 1:
                raise ValueError
        except ValueError:
            flash("ICMP timeout and API workers must be positive integers.",
                  "error")
            return redirect(url_for("settings_scanner"))

        editor.update_section("scanner", {
            "enabled":          "true" if f.get("enabled") == "on" else "false",
            "schedule":         sched,
            "subnets":          ",".join(_csv(f.get("subnets") or "")),
            "exclude_suffixes": ",".join(_csv(f.get("exclude_suffixes") or "")),
            "filter_keywords":  ",".join(_csv(f.get("filter_keywords") or "")),
            "device_file":      (f.get("device_file") or "").strip(),
            "ip_list_output":   (f.get("ip_list_output") or "").strip(),
            "icmp_timeout":     str(timeout),
            "verify_via_api":   "true" if f.get("verify_via_api") == "on" else "false",
            "api_workers":      str(workers),
        })
        log.info("Web UI: scanner settings updated by user=%s", session.get("user"))
        flash("Scanner settings saved. Restart the agent to apply.", "success")
        return redirect(url_for("settings_scanner"))

    # ── Config Backup ─────────────────────────────────────────────────────

    @app.get("/settings/backup")
    @require_login
    def settings_backup():
        if editor is None:
            abort(404)
        live = editor.read()
        b = live["backup"] if live.has_section("backup") else {}
        ctx = _settings_context()
        ctx.update({
            "enabled":        b.get("enabled",        "true").lower() == "true",
            "schedule":       b.get("schedule",       "02:00"),
            "ip_list":        b.get("ip_list",
                                    "/var/lib/aruba-agent/ip_list.txt"),
            "backup_path":    b.get("backup_path",
                                    "/var/lib/aruba-agent/backups"),
            "retention_days": b.get("retention_days", "7"),
            "api_version":    b.get("api_version",    ""),
            "errors":         get_flashed_messages(category_filter=["error"]),
            "messages":       get_flashed_messages(category_filter=["success"]),
        })
        return render_template("settings_backup.html", **ctx)

    @app.post("/settings/backup")
    @require_login
    def settings_backup_post():
        guard = _editor_required()
        if guard is not None: return guard

        f = request.form
        sched = _validate_hhmm(f.get("schedule") or "")
        if sched is None:
            flash("Schedule must be HH:MM (24-hour).", "error")
            return redirect(url_for("settings_backup"))
        try:
            retention = int(f.get("retention_days") or "7")
            if retention < 1:
                raise ValueError
        except ValueError:
            flash("Retention days must be a positive integer.", "error")
            return redirect(url_for("settings_backup"))

        values = {
            "enabled":        "true" if f.get("enabled") == "on" else "false",
            "schedule":       sched,
            "ip_list":        (f.get("ip_list") or "").strip(),
            "backup_path":    (f.get("backup_path") or "").strip(),
            "retention_days": str(retention),
        }
        api_v = (f.get("api_version") or "").strip()
        remove: List[str] = []
        if api_v:
            values["api_version"] = api_v
        else:
            remove.append("api_version")

        editor.update_section("backup", values, remove_keys=remove)
        log.info("Web UI: backup settings updated by user=%s", session.get("user"))
        flash("Backup settings saved. Restart the agent to apply.", "success")
        return redirect(url_for("settings_backup"))

    # ── Firmware ──────────────────────────────────────────────────────────

    @app.get("/settings/firmware")
    @require_login
    def settings_firmware():
        if editor is None:
            abort(404)
        live = editor.read()
        fw = live["firmware"] if live.has_section("firmware") else {}
        ctx = _settings_context()
        ctx.update({
            "ip_list":        fw.get("ip_list",
                                     "/var/lib/aruba-agent/ip_list.txt"),
            "target_version": fw.get("target_version", ""),
            "image_path":     fw.get("image_path",     ""),
            "max_workers":    fw.get("max_workers",    "2"),
            "errors":         get_flashed_messages(category_filter=["error"]),
            "messages":       get_flashed_messages(category_filter=["success"]),
        })
        return render_template("settings_firmware.html", **ctx)

    @app.post("/settings/firmware")
    @require_login
    def settings_firmware_post():
        guard = _editor_required()
        if guard is not None: return guard

        f = request.form
        try:
            workers = int(f.get("max_workers") or "2")
            if workers < 1:
                raise ValueError
        except ValueError:
            flash("Max workers must be a positive integer.", "error")
            return redirect(url_for("settings_firmware"))

        editor.update_section("firmware", {
            "ip_list":        (f.get("ip_list") or "").strip(),
            "target_version": (f.get("target_version") or "").strip(),
            "image_path":     (f.get("image_path") or "").strip(),
            "max_workers":    str(workers),
        })
        log.info("Web UI: firmware settings updated by user=%s",
                 session.get("user"))
        flash("Firmware settings saved. Restart the agent to apply.", "success")
        return redirect(url_for("settings_firmware"))

    # ── Web Server ────────────────────────────────────────────────────────

    @app.get("/settings/web")
    @require_login
    def settings_web():
        if editor is None:
            abort(404)
        live = editor.read()
        w = live["web"]   if live.has_section("web")   else {}
        a = live["agent"] if live.has_section("agent") else {}
        ctx = _settings_context()
        ctx.update({
            "host":                  w.get("host",                  "127.0.0.1"),
            "port":                  w.get("port",                  "8080"),
            "threads":               w.get("threads",               "8"),
            "session_timeout_hours": w.get("session_timeout_hours", "8"),
            "secure_cookies":        w.get("secure_cookies",        "true").lower() == "true",
            "trust_proxy_headers":   w.get("trust_proxy_headers",   "true").lower() == "true",
            "secret_key_set":        bool(w.get("secret_key", "").strip()),
            "state_file":            a.get("state_file",
                                           "/var/lib/aruba-agent/state.json"),
            "errors":                get_flashed_messages(category_filter=["error"]),
            "messages":              get_flashed_messages(category_filter=["success"]),
        })
        return render_template("settings_web.html", **ctx)

    @app.post("/settings/web")
    @require_login
    def settings_web_post():
        guard = _editor_required()
        if guard is not None: return guard

        f = request.form
        try:
            port    = int(f.get("port")                  or "8080")
            threads = int(f.get("threads")               or "8")
            timeout = int(f.get("session_timeout_hours") or "8")
            if not (1 <= port <= 65535) or threads < 1 or timeout < 1:
                raise ValueError
        except ValueError:
            flash("Port, threads, and session timeout must be positive integers; "
                  "port in 1–65535.", "error")
            return redirect(url_for("settings_web"))

        live = editor.read()
        existing_secret = (live["web"]["secret_key"]
                           if live.has_section("web") and
                              live.has_option("web", "secret_key")
                           else "")

        regen = f.get("regenerate_secret") == "on"
        if regen:
            new_secret = secrets.token_urlsafe(48)
        else:
            new_secret = existing_secret

        editor.update_section("web", {
            "host":                  (f.get("host") or "127.0.0.1").strip(),
            "port":                  str(port),
            "threads":               str(threads),
            "secret_key":            new_secret,
            "session_timeout_hours": str(timeout),
            "secure_cookies":        "true" if f.get("secure_cookies")      == "on" else "false",
            "trust_proxy_headers":   "true" if f.get("trust_proxy_headers") == "on" else "false",
        })
        editor.update_section("agent", {
            "state_file": (f.get("state_file") or
                           "/var/lib/aruba-agent/state.json").strip(),
        })

        log.info("Web UI: web settings updated by user=%s (secret_regenerated=%s)",
                 session.get("user"), regen)
        if regen:
            flash("Web settings saved AND a new secret_key was generated. "
                  "Existing sessions will be invalidated when the agent restarts.",
                  "success")
        else:
            flash("Web settings saved. Restart the agent to apply.", "success")
        return redirect(url_for("settings_web"))

    # ── ARP Discovery (multi-section: [arp.<location>]) ────────────────────

    def _arp_locations(live_cfg: configparser.ConfigParser) -> List[dict]:
        out = []
        for sec in live_cfg.sections():
            if not sec.startswith("arp."):
                continue
            name = sec[len("arp."):]
            s    = live_cfg[sec]
            out.append({
                "name":       name,
                "section":    sec,
                "enabled":    s.get("enabled",  "true").lower() == "true",
                "schedule":   s.get("schedule", "01:00"),
                "routers":    s.get("routers",  ""),
                "ip_list":    s.get("ip_list",  ""),
                "output_dir": s.get("output_dir",
                                    f"/var/lib/aruba-agent/arp/{name}"),
            })
        out.sort(key=lambda x: x["name"])
        return out

    @app.get("/settings/arp")
    @require_login
    def settings_arp():
        if editor is None:
            abort(404)
        live = editor.read()
        ctx  = _settings_context()
        ctx.update({
            "locations": _arp_locations(live),
            "errors":    get_flashed_messages(category_filter=["error"]),
            "messages":  get_flashed_messages(category_filter=["success"]),
        })
        return render_template("settings_arp.html", **ctx)

    @app.post("/settings/arp/<location>")
    @require_login
    def settings_arp_save(location: str):
        guard = _editor_required()
        if guard is not None: return guard
        if not _LOCATION_NAME.match(location):
            abort(400)

        f = request.form
        sched = _validate_hhmm(f.get("schedule") or "")
        if sched is None:
            flash("Schedule must be HH:MM (24-hour).", "error")
            return redirect(url_for("settings_arp"))

        ok, bad = _validate_ips(f.get("routers") or "")
        if not ok:
            flash(f"Invalid router IP(s): {', '.join(bad)}", "error")
            return redirect(url_for("settings_arp"))

        section = f"arp.{location}"
        editor.update_section(section, {
            "enabled":    "true" if f.get("enabled") == "on" else "false",
            "schedule":   sched,
            "routers":    ",".join(_csv(f.get("routers") or "")),
            "ip_list":    (f.get("ip_list") or "").strip(),
            "output_dir": (f.get("output_dir") or
                           f"/var/lib/aruba-agent/arp/{location}").strip(),
        })
        log.info("Web UI: ARP location '%s' saved by user=%s",
                 location, session.get("user"))
        flash(f"Location '{location}' saved. Restart the agent to apply.",
              "success")
        return redirect(url_for("settings_arp"))

    @app.post("/settings/arp/add")
    @require_login
    def settings_arp_add():
        guard = _editor_required()
        if guard is not None: return guard

        name = (request.form.get("location_name") or "").strip().lower()
        if not name or not _LOCATION_NAME.match(name):
            flash("Location name must be alphanumeric "
                  "(plus . _ -). Try 'main-campus'.", "error")
            return redirect(url_for("settings_arp"))

        live = editor.read()
        if live.has_section(f"arp.{name}"):
            flash(f"Location '{name}' already exists.", "error")
            return redirect(url_for("settings_arp"))

        editor.update_section(f"arp.{name}", {
            "enabled":    "true",
            "schedule":   "01:00",
            "routers":    "",
            "ip_list":    f"/etc/aruba-agent/subnets/{name}_ip_list.txt",
            "output_dir": f"/var/lib/aruba-agent/arp/{name}",
        })
        log.info("Web UI: ARP location '%s' added by user=%s",
                 name, session.get("user"))
        flash(f"Location '{name}' added. Fill in routers and "
              "subnet list, then save.", "success")
        return redirect(url_for("settings_arp"))

    @app.post("/settings/arp/<location>/remove")
    @require_login
    def settings_arp_remove(location: str):
        guard = _editor_required()
        if guard is not None: return guard
        if not _LOCATION_NAME.match(location):
            abort(400)

        live   = editor.read()
        header = editor.read_header()
        section = f"arp.{location}"
        if not live.has_section(section):
            flash(f"Location '{location}' does not exist.", "error")
        else:
            live.remove_section(section)
            editor.save(live, header=header)
            log.info("Web UI: ARP location '%s' removed by user=%s",
                     location, session.get("user"))
            flash(f"Location '{location}' removed. Restart the agent to apply.",
                  "success")
        return redirect(url_for("settings_arp"))

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

    # ── SNMP profile management (C6.3) ───────────────────────────────────────

    @app.get("/api/snmp/profiles")
    @require_login
    def api_snmp_profiles():
        """List the SNMP profiles the registry currently knows about,
        and which one is the default. Used by the dashboard's per-
        switch profile-pinning dropdown."""
        if snmp_agent is None:
            return jsonify({
                "enabled": False,
                "profiles": [],
                "default":  None,
            })
        return jsonify({
            "enabled":  True,
            "profiles": snmp_agent.registry.names(),
            "default":  snmp_agent.registry.default_name or None,
        })

    @app.post("/api/switches/<switch_name>/profile")
    @require_login
    def api_set_switch_profile(switch_name: str):
        """
        Pin (or clear) the SNMP profile for a single switch.

        JSON body:
            { "profile": "aruba" }   — pin to the 'aruba' profile
            { "profile": "" }        — clear; let detection re-run
            { "profile": null }      — clear; let detection re-run

        Returns the resulting profile field on success, 404 if the
        switch isn't tracked, 400 if the profile name isn't in the
        registry.
        """
        if switch_name not in state.switches:
            abort(404)

        payload = request.get_json(silent=True) or {}
        profile = (payload.get("profile") or "").strip()

        # Validate against the registry — except for the empty string
        # which is a valid "clear pin" signal.
        if profile and snmp_agent is not None:
            if profile not in snmp_agent.registry:
                return jsonify({
                    "error": f"Unknown SNMP profile {profile!r}. "
                             f"Available: {snmp_agent.registry.names()}",
                }), 400

        if not state.set_switch_profile(switch_name, profile):
            abort(404)

        log.info("Web UI: SNMP profile for %s set to %r by user=%s",
                 switch_name, profile or "<auto-detect>", session.get("user"))
        return jsonify({
            "status":  "ok",
            "switch":  switch_name,
            "profile": profile,
        })

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

    @app.get("/api/arp/locations")
    @require_login
    def api_arp_locations():
        """Names of every enabled [arp.<location>] section the agent
        knows how to run. Used by the dashboard to render per-location
        Run Now buttons next to the last_run timestamps."""
        return jsonify({"locations": sorted(arp_fns.keys()) if arp_fns else []})

    # Match the same name validation used elsewhere in the agent —
    # locations are alphanumeric plus . _ -
    _ARP_LOCATION_NAME = re.compile(r"^[a-zA-Z0-9._-]+$")

    @app.post("/api/arp/<location>/trigger")
    @require_login
    def api_arp_trigger(location: str):
        """Run an ARP discovery task on demand. Mirrors
        /api/scanner/trigger for the scanner."""
        if not arp_fns:
            return jsonify({"error": "No ARP locations configured"}), 503
        if not _ARP_LOCATION_NAME.match(location):
            abort(400)
        fn = arp_fns.get(location)
        if fn is None:
            return jsonify({"error":
                f"ARP location {location!r} not found. Available: "
                f"{sorted(arp_fns.keys())}"}), 404
        _run_in_thread(fn, f"manual-arp-{location}")
        log.info("Web UI: manual ARP run for %s triggered by user=%s",
                 location, session.get("user"))
        return jsonify({"status": "triggered", "location": location})

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
            #
            # asyncore_use_poll=True is critical at fleet scale.
            # Default is False, which makes waitress's poll loop call
            # select.select() — that crashes with
            #     ValueError: filedescriptor out of range in select()
            # whenever ANY fd in the watched set exceeds FD_SETSIZE
            # (1024 on Linux). With ~200 SwitchMonitor threads each
            # holding a cached pysnmp engine + asyncio dispatcher
            # plus pysnmp's per-call UDP socket churn, the agent
            # routinely climbs past 1024 fds and waitress's listening
            # socket ends up with fd > 1023. Result: web-ui thread
            # dies with the ValueError, listener stays bound (socket
            # is still open) but nothing ever calls accept() on it,
            # Apache hits its 60s ProxyTimeout and returns 502.
            #
            # asyncore_use_poll=True swaps in select.poll() which has
            # no FD_SETSIZE limit. Same blocking semantics, no cap.
            asyncore_use_poll = True,
        )

    threading.Thread(target=_run_prod, name="web-ui", daemon=True).start()
    log.info(
        "Web UI (waitress, %d threads) available at http://%s:%d",
        threads, host if host != "0.0.0.0" else "localhost", port,
    )
