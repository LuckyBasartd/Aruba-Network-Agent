"""
SNMPv3 read-only operations for vendor-neutral switch monitoring.

Why this module exists
----------------------
Up through v2.1.0 the reachability poller opened an AOS-CX REST
session (login + GET + logout) every 30 seconds for every switch.
That works but it's a lot of management-plane churn — and any logout
glitch spirals into the "maximum session limit reached" symptom we
saw in production.

SNMPv3 sysUpTime.0 is a single UDP exchange: one Get-Request, one
Get-Response. No session state on the switch, no login/logout
contract, identical OIDs across Aruba / Cisco / Arista. Using it for
the 30s reachability poll is the right call.

Scope
-----
This module is intentionally read-only. We use SNMP to:
  * answer "is this device responding?" (sysUpTime.0)
  * read the configured hostname (sysName.0)
  * read sysObjectID for vendor identification (used by C3 detector)
  * read sysDescr as a fallback hint

Anything that requires writes (config push, save mem, firmware) goes
through the vendor driver — SNMP-write is rarely enabled and not
worth the security tradeoff.

pysnmp is imported lazily inside .get() so an install missing the
package still loads the rest of the agent. The module logs a
warning when SNMP is requested but pysnmp is missing.
"""

from __future__ import annotations

import logging
from configparser import ConfigParser
from dataclasses  import dataclass
from typing       import Optional


log = logging.getLogger(__name__)


# ─── standard MIB-2 OIDs ─────────────────────────────────────────────────────
# 1.3.6.1.2.1.1 = SNMPv2-MIB::system

OID_SYS_DESCR     = "1.3.6.1.2.1.1.1.0"   # vendor + model + version string
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"   # vendor-assigned enterprise OID
OID_SYS_UPTIME    = "1.3.6.1.2.1.1.3.0"   # centiseconds since last boot
OID_SYS_NAME      = "1.3.6.1.2.1.1.5.0"   # configured hostname


# ─── credentials ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SnmpV3Credentials:
    """
    SNMPv3 USM credentials. Match what the switches expect.

    Auth protocols: NONE / MD5 / SHA / SHA224 / SHA256 / SHA384 / SHA512
    Priv protocols: NONE / DES / AES128 / AES192 / AES256

    The security level is derived from which passwords are filled in:
      * both auth + priv  →  authPriv          (recommended)
      *      auth         →  authNoPriv        (auth only, no encryption)
      * neither           →  noAuthNoPriv      (debug / lab only — discouraged)

    Context fields
    --------------
    `username` is the USM Security Name — the thing both ends of the
    conversation agree on as "this user".

    `context_name` is the SNMPv3 logical context to query. Default is
    the empty string, which is what most installations need. Cisco
    IOS-XE in particular sometimes requires a non-default context
    (e.g. when SNMP views are scoped to a VRF).

    `context_engine_id` is normally left blank — pysnmp discovers the
    remote engine ID for you. Provide a hex string only if your switch
    rejects the auto-discovery handshake. Format: hex without
    separators, e.g. "80000009030001a2b3c4d5e6".
    """
    username:          str
    auth_protocol:     str = "SHA"
    auth_password:     str = ""
    priv_protocol:     str = "AES128"
    priv_password:     str = ""
    context_name:      str = ""
    context_engine_id: str = ""

    @property
    def security_level(self) -> str:
        if self.auth_password and self.priv_password:
            return "authPriv"
        if self.auth_password:
            return "authNoPriv"
        return "noAuthNoPriv"


# ─── agent ───────────────────────────────────────────────────────────────────

class SnmpAgent:
    """
    Stateless SNMPv3 client. Construct once with the operator's
    credentials, then call .get() / .is_reachable() / etc. for any
    host. pysnmp's SnmpEngine is created per-call; that's fine for
    our 30s poll cadence and avoids cross-thread engine sharing.
    """

    def __init__(
        self,
        creds:   SnmpV3Credentials,
        port:    int = 161,
        timeout: int = 2,
        retries: int = 1,
    ) -> None:
        self._creds   = creds
        self._port    = port
        self._timeout = timeout
        self._retries = retries

    # ─── low-level GET ───────────────────────────────────────────────────────

    def get(self, host: str, oid: str) -> Optional[str]:
        """
        SNMPv3 GET. Returns the variable value as a string (whatever
        pysnmp's prettyPrint produces) or None on any failure —
        timeout, auth error, no-such-object, missing pysnmp.

        Designed to never raise: callers can wrap a poll in this and
        treat a None as "device unreachable" without exception
        handling.
        """
        try:
            from pysnmp.hlapi import (
                getCmd, SnmpEngine, UsmUserData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity,
                usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
                usmHMAC128SHA224AuthProtocol, usmHMAC192SHA256AuthProtocol,
                usmHMAC256SHA384AuthProtocol, usmHMAC384SHA512AuthProtocol,
                usmDESPrivProtocol, usmAesCfb128Protocol,
                usmAesCfb192Protocol, usmAesCfb256Protocol,
                usmNoAuthProtocol, usmNoPrivProtocol,
            )
            from pyasn1.type.univ import OctetString
        except ImportError:
            log.warning(
                "pysnmp not installed — SNMP unavailable. "
                "Install with: pip3 install pysnmp"
            )
            return None

        auth_map = {
            "NONE":   usmNoAuthProtocol,
            "MD5":    usmHMACMD5AuthProtocol,
            "SHA":    usmHMACSHAAuthProtocol,
            "SHA224": usmHMAC128SHA224AuthProtocol,
            "SHA256": usmHMAC192SHA256AuthProtocol,
            "SHA384": usmHMAC256SHA384AuthProtocol,
            "SHA512": usmHMAC384SHA512AuthProtocol,
        }
        priv_map = {
            "NONE":   usmNoPrivProtocol,
            "DES":    usmDESPrivProtocol,
            "AES128": usmAesCfb128Protocol,
            "AES192": usmAesCfb192Protocol,
            "AES256": usmAesCfb256Protocol,
        }
        auth_proto = auth_map.get(self._creds.auth_protocol.upper(),
                                  usmHMACSHAAuthProtocol)
        priv_proto = priv_map.get(self._creds.priv_protocol.upper(),
                                  usmAesCfb128Protocol)

        # Map the credential combination onto the right USM user_data shape.
        if self._creds.auth_password and self._creds.priv_password:
            user_data = UsmUserData(
                self._creds.username,
                self._creds.auth_password,
                self._creds.priv_password,
                authProtocol=auth_proto,
                privProtocol=priv_proto,
            )
        elif self._creds.auth_password:
            user_data = UsmUserData(
                self._creds.username,
                self._creds.auth_password,
                authProtocol=auth_proto,
                privProtocol=usmNoPrivProtocol,
            )
        else:
            user_data = UsmUserData(
                self._creds.username,
                authProtocol=usmNoAuthProtocol,
                privProtocol=usmNoPrivProtocol,
            )

        # Build ContextData. Empty contextName / blank engine ID =
        # pysnmp defaults (auto-discover engine ID, default context).
        context_engine_id = None
        if self._creds.context_engine_id:
            try:
                context_engine_id = OctetString(
                    hexValue=self._creds.context_engine_id.replace(":", "").strip()
                )
            except Exception as exc:
                log.warning("SNMP: invalid context_engine_id %r — %s",
                            self._creds.context_engine_id, exc)
                return None
        context_data = ContextData(
            contextEngineId=context_engine_id,
            contextName=self._creds.context_name,
        )

        try:
            iterator = getCmd(
                SnmpEngine(),
                user_data,
                UdpTransportTarget(
                    (host, self._port),
                    timeout=self._timeout,
                    retries=self._retries,
                ),
                context_data,
                ObjectType(ObjectIdentity(oid)),
            )
            error_indication, error_status, _err_idx, var_binds = next(iterator)
        except Exception as exc:
            log.debug("SNMP GET %s on %s raised: %s", oid, host, exc)
            return None

        if error_indication:
            log.debug("SNMP GET %s on %s: %s", oid, host, error_indication)
            return None
        if error_status:
            log.debug("SNMP GET %s on %s: PDU error %s",
                      oid, host, error_status.prettyPrint())
            return None
        for _name, val in var_binds:
            return val.prettyPrint()
        return None

    # ─── high-level helpers ──────────────────────────────────────────────────

    def is_reachable(self, host: str) -> bool:
        """True if sysUpTime.0 came back. The actual value is irrelevant
        for reachability — receiving any response means the SNMP engine
        on the switch is alive and authenticated us successfully."""
        return self.get(host, OID_SYS_UPTIME) is not None

    def get_uptime_centiseconds(self, host: str) -> Optional[int]:
        v = self.get(host, OID_SYS_UPTIME)
        if v is None:
            return None
        try:
            return int(v)
        except ValueError:
            return None

    def get_sys_name(self, host: str) -> Optional[str]:
        """Configured hostname. Equivalent to AOS-CX /system.hostname,
        Cisco IOS `hostname`, Arista EOS `hostname` config line."""
        return self.get(host, OID_SYS_NAME)

    def get_sys_descr(self, host: str) -> Optional[str]:
        """Free-form vendor string — used as fallback when sysObjectID
        doesn't match our known-vendor table."""
        return self.get(host, OID_SYS_DESCR)

    def get_sys_object_id(self, host: str) -> Optional[str]:
        """Vendor's enterprise OID under 1.3.6.1.4.1.<n>. C3's vendor
        detector keys off this."""
        return self.get(host, OID_SYS_OBJECT_ID)


# ─── config helper ───────────────────────────────────────────────────────────

def from_config(cfg: ConfigParser) -> Optional[SnmpAgent]:
    """
    Build an SnmpAgent from the [snmp] section of config.ini.
    Returns None when:
      * the section is missing
      * enabled = false
      * username is blank (we'd never authenticate)

    Callers that get None should fall back to whatever non-SNMP
    polling they used before.
    """
    if not cfg.has_section("snmp"):
        return None
    s = cfg["snmp"]
    if s.get("enabled", "false").strip().lower() not in ("true", "1", "yes", "on"):
        return None

    username = s.get("username", "").strip()
    if not username:
        log.warning("[snmp] enabled but username is empty — SNMP disabled")
        return None

    creds = SnmpV3Credentials(
        username          = username,
        auth_protocol     = s.get("auth_protocol", "SHA").strip(),
        auth_password     = s.get("auth_password", ""),
        priv_protocol     = s.get("priv_protocol", "AES128").strip(),
        priv_password     = s.get("priv_password", ""),
        context_name      = s.get("context_name", "").strip(),
        context_engine_id = s.get("context_engine_id", "").strip(),
    )
    return SnmpAgent(
        creds   = creds,
        port    = int(s.get("port",    "161")),
        timeout = int(s.get("timeout", "2")),
        retries = int(s.get("retries", "1")),
    )
