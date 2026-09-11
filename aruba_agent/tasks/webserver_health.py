"""
AOS-8 web-server health check (VPN controller).

The VPN controller's web management service has been intermittently
failing — `show web-server statistics` returns:

    Error in fetching statistics, Web Server is not responding

This job SSHes to the controller on a schedule, runs that command, and
emails an alert when the web-server is down (error string present, empty
output, or the SSH/command itself fails). Alert-only — it does not try
to restart anything.

Self-contained: independent of the poller/backup, imported only when
[webserver_health] enabled = true. Uses the aos8 driver over SSH.
"""

from __future__ import annotations

import configparser
import logging
from typing import List

from aruba_agent.notifier      import EmailNotifier
from aruba_agent.secrets_store import decrypt as _decrypt

log = logging.getLogger(__name__)

_DEFAULT_FAILS = ("not responding", "error in fetching")


class WebServerHealthTask:
    """Periodic `show web-server statistics` health check for an AOS-8 box."""

    def __init__(self, cfg: configparser.ConfigParser, notifier: EmailNotifier) -> None:
        w  = cfg["webserver_health"] if "webserver_health" in cfg else {}
        cr = cfg["credentials"]      if "credentials"      in cfg else {}
        a8 = cfg["credentials.aos8"] if "credentials.aos8" in cfg else {}

        self.notifier = notifier
        self.host     = (w.get("host", "") or "").strip()
        self.command  = (w.get("command", "show web-server statistics") or
                         "show web-server statistics").strip()
        self.device_type = (w.get("device_type", "aruba_os") or "aruba_os").strip()
        self.username = (w.get("username", "") or a8.get("username", "") or
                         cr.get("username", "admin")).strip()
        self.password = (_decrypt(w.get("password", "")) or
                         _decrypt(a8.get("password", "")) or
                         _decrypt(cr.get("password", "")))
        self.enable_secret = _decrypt(w.get("enable_secret", "")) or _decrypt(a8.get("enable_secret", ""))
        self.timeout  = int(_num(w.get("timeout", "30"), 30))
        self.fail_patterns = [p.strip().lower() for p in
                              (w.get("fail_patterns", "") or "").split(",") if p.strip()] \
                             or list(_DEFAULT_FAILS)

    # -- collection -----------------------------------------------------------

    def _run_command(self):
        """SSH to the controller and run the check command.
        Returns (ok: bool, output: str, error: str)."""
        try:
            from netmiko import ConnectHandler          # lazy
        except ImportError as exc:
            return False, "", f"netmiko not installed ({exc})"

        params = {
            "device_type": self.device_type,
            "host":        self.host,
            "username":    self.username,
            "password":    self.password,
            "timeout":     self.timeout,
            "fast_cli":    False,
        }
        if self.enable_secret:
            params["secret"] = self.enable_secret

        net = None
        try:
            net = ConnectHandler(**params)
            if self.enable_secret:
                try:
                    net.enable()
                except Exception:
                    pass
            try:
                net.clear_buffer()
            except Exception:
                pass
            try:
                out = net.send_command(self.command, read_timeout=60)
            except TypeError:
                out = net.send_command(self.command)
            return True, (out or ""), ""
        except Exception as exc:
            return False, "", f"{type(exc).__name__}: {exc}"
        finally:
            if net is not None:
                try:
                    net.disconnect()
                except Exception:
                    pass

    def evaluate(self, ok: bool, output: str, error: str) -> bool:
        """Return True when the web-server is HEALTHY. Pure/testable."""
        if not ok:
            return False              # couldn't even run the command
        low = (output or "").lower()
        if not low.strip():
            return False              # empty response
        if any(p in low for p in self.fail_patterns):
            return False
        return True

    # -- run ------------------------------------------------------------------

    def run(self) -> None:
        if not self.host:
            log.warning("webserver_health: no host configured — skipping")
            return
        ok, output, error = self._run_command()
        healthy = self.evaluate(ok, output, error)
        if healthy:
            log.info("webserver_health: %s web-server OK", self.host)
            return

        reason = error or (output.strip() or "empty response")
        log.error("webserver_health: %s web-server UNHEALTHY: %s", self.host, reason)
        body = (
            f"The web-server on the AOS-8 controller {self.host} appears to be "
            f"DOWN.\n\n"
            f"Command:  {self.command}\n"
            f"Result:\n  {reason}\n\n"
            "This is the intermittent web-server failure being tracked. Log in "
            "and restart the web service if needed."
        )
        self.notifier.send(
            f"[Network Agent] VPN controller web-server not responding ({self.host})",
            body,
        )


def _num(val, default):
    try:
        return float(str(val).strip())
    except (TypeError, ValueError):
        return default
