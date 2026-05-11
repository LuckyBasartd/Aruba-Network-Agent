"""
RADIUS PAP authenticator.

Wraps pyrad to validate (username, password) pairs against an external RADIUS
server. Uses the classic PAP flow on UDP 1812.

Config section (in config.ini):

    [radius]
    enabled        = true
    server         = 10.0.0.50
    secret         = SharedSecretHere
    port           = 1812
    nas_identifier = aruba-switch-manager
    timeout        = 5
    retries        = 2

If `enabled = false` (or the [radius] section is missing), `authenticate()`
always returns False — the login page will be unusable until the admin fills
in a valid RADIUS server. This is intentional: there is no local-account
fallback in production mode.
"""

from __future__ import annotations

import configparser
import io
import logging
import socket
from typing import Optional

from aruba_agent.secrets_store import decrypt as _decrypt

log = logging.getLogger(__name__)

# Minimal inline RADIUS dictionary.  Just enough attributes for a PAP
# Access-Request.  Keeping it inline means no on-disk dictionary file is
# required — the service runs out of the box.
_RADIUS_DICT = """\
ATTRIBUTE    User-Name          1    string
ATTRIBUTE    User-Password      2    string
ATTRIBUTE    NAS-IP-Address     4    ipaddr
ATTRIBUTE    NAS-Port           5    integer
ATTRIBUTE    Service-Type       6    integer
ATTRIBUTE    Reply-Message      18   string
ATTRIBUTE    NAS-Identifier     32   string
ATTRIBUTE    NAS-Port-Type      61   integer

VALUE        Service-Type       Login-User          1
VALUE        Service-Type       Authenticate-Only   8
VALUE        NAS-Port-Type      Virtual             5
"""


class RadiusAuthenticator:
    """Validates credentials against a RADIUS server using PAP."""

    def __init__(self, config: configparser.ConfigParser) -> None:
        section = "radius"
        self.enabled = False
        self.server: Optional[str] = None
        self.secret: Optional[bytes] = None
        self.port = 1812
        self.timeout = 5
        self.retries = 2
        self.nas_identifier = socket.gethostname() or "aruba-switch-manager"

        if section not in config:
            log.warning(
                "No [radius] section found — RADIUS auth disabled. "
                "Add a [radius] block to config.ini to enable login."
            )
            return

        rc = config[section]
        self.enabled        = rc.getboolean("enabled", fallback=False)
        self.server         = rc.get("server", fallback="").strip() or None
        # The shared secret may be encrypted at rest (enc:<token>) in
        # v3.0.1+ deployments. Decrypt before encoding so pyrad sees
        # the actual secret bytes.
        secret              = _decrypt(rc.get("secret", fallback="").strip())
        self.secret         = secret.encode("utf-8") if secret else None
        self.port           = rc.getint("port", fallback=1812)
        self.timeout        = rc.getint("timeout", fallback=5)
        self.retries        = rc.getint("retries", fallback=2)
        self.nas_identifier = rc.get("nas_identifier", fallback=self.nas_identifier).strip()

        if self.enabled and (not self.server or not self.secret):
            log.error(
                "RADIUS enabled but server/secret not configured — "
                "authentication will fail."
            )
            self.enabled = False

        if self.enabled:
            log.info(
                "RADIUS authenticator initialised: server=%s port=%d nas_id=%s",
                self.server, self.port, self.nas_identifier,
            )

    # ------------------------------------------------------------------

    def is_configured(self) -> bool:
        """True if this authenticator has a usable server + secret."""
        return bool(self.enabled and self.server and self.secret)

    def authenticate(self, username: str, password: str) -> bool:
        """
        Return True if the RADIUS server returns Access-Accept for (user, pw).

        Never logs the password. Logs only username + result + server response
        type on failure for audit purposes.
        """
        if not self.is_configured():
            log.warning("RADIUS auth attempt rejected — authenticator not configured.")
            return False

        if not username or not password:
            log.info("RADIUS auth rejected — empty username or password.")
            return False

        # Lazy import so the agent still starts without pyrad installed;
        # the admin only needs pyrad if they enable RADIUS.
        try:
            from pyrad.client     import Client
            from pyrad.dictionary import Dictionary
            import pyrad.packet   as packet
        except ImportError as exc:
            log.error(
                "pyrad is not installed — run `pip install pyrad` to enable "
                "RADIUS authentication (%s).", exc,
            )
            return False

        try:
            dictionary = Dictionary(io.StringIO(_RADIUS_DICT))
            client = Client(
                server     = self.server,
                authport   = self.port,
                secret     = self.secret,
                dict       = dictionary,
            )
            client.timeout = self.timeout
            client.retries = self.retries

            req = client.CreateAuthPacket(
                code           = packet.AccessRequest,
                User_Name      = username,
                NAS_Identifier = self.nas_identifier,
            )
            # PAP: password is encrypted by the pyrad helper using the
            # shared secret + request authenticator.
            req["User-Password"] = req.PwCrypt(password)

            reply = client.SendPacket(req)

            if reply.code == packet.AccessAccept:
                log.info("RADIUS auth SUCCESS for user=%s", username)
                return True

            # AccessReject, AccessChallenge, or anything else → deny.
            log.info(
                "RADIUS auth FAIL for user=%s (reply code=%s)",
                username, reply.code,
            )
            return False

        except Exception as exc:
            # Network timeout, bad secret, malformed reply, etc.
            log.error(
                "RADIUS auth error for user=%s: %s", username, exc,
            )
            return False
