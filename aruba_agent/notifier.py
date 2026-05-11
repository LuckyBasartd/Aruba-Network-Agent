"""
SMTP email notifier — shared by all agent features.
Thread-safe: a single lock serialises SMTP connections.
"""

from __future__ import annotations

import configparser
import smtplib
import threading
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List

from aruba_agent.secrets_store import cfg_get as _cfg_get

log = logging.getLogger(__name__)


class EmailNotifier:
    def __init__(self, cfg: configparser.ConfigParser) -> None:
        # Use cfg.get(section, key, fallback=...) so missing sections never crash
        self.enabled  = cfg.getboolean("smtp", "enabled",  fallback=True)
        self.host     = cfg.get("smtp",     "host",     fallback="localhost")
        self.port     = cfg.getint("smtp",  "port",     fallback=587)
        self.use_tls  = cfg.getboolean("smtp", "use_tls", fallback=True)
        self.username = cfg.get("smtp",     "username", fallback="")
        # Password is decrypted at read time if stored as enc:...
        # Cleartext values pass through unchanged (back-compat with
        # pre-v3.0.1 configs that haven't been migrated yet).
        self.password = _cfg_get(cfg, "smtp", "password", fallback="")
        self.from_    = cfg.get("smtp",     "from",     fallback=self.username)
        self.to: List[str] = [
            a.strip()
            for a in cfg.get("smtp", "to", fallback="").split(",")
            if a.strip()
        ]
        self._lock = threading.Lock()

    def send(self, subject: str, body: str) -> None:
        if not self.enabled:
            log.debug("Email notifications disabled — skipping: %s", subject)
            return
        if not self.to:
            log.warning("No recipients configured — skipping: %s", subject)
            return
        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"]    = self.from_
        msg["To"]      = ", ".join(self.to)
        msg.attach(MIMEText(body, "plain"))
        with self._lock:
            try:
                if self.use_tls:
                    srv = smtplib.SMTP(self.host, self.port, timeout=10)
                    srv.ehlo()
                    srv.starttls()
                else:
                    srv = smtplib.SMTP(self.host, self.port, timeout=10)
                if self.username:
                    srv.login(self.username, self.password)
                srv.sendmail(self.from_, self.to, msg.as_string())
                srv.quit()
                log.info("Email sent: %s", subject)
            except Exception as exc:
                log.error("Email failed '%s': %s", subject, exc)
