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

import asyncio
import logging
import threading
from configparser import ConfigParser
from dataclasses  import dataclass
from typing       import Optional


log = logging.getLogger(__name__)


def _ensure_thread_event_loop() -> None:
    """
    pysnmp's synchronous hlapi (getCmd in 5.x and 6.x) is implemented
    on top of asyncio. It needs an event loop in the current thread.

    On the main thread Python 3.12 still gives you one for free. In a
    worker thread (ThreadPoolExecutor, the one-thread-per-switch
    SwitchMonitor model in this project, etc.) there isn't a default
    event loop, and asyncio.get_event_loop() raises RuntimeError. That
    surfaces as engine_error with TypeError or RuntimeError detail.

    Call this at the top of any code path that touches pysnmp from a
    thread other than __main__.
    """
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        # No loop in this thread yet — create one and bind it.
        # We deliberately don't close it: pysnmp may reuse it across
        # successive .get() calls from the same thread, and Python's
        # event loop machinery copes with idle loops.
        asyncio.set_event_loop(asyncio.new_event_loop())


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
        per_vendor_context: Optional[dict] = None,
    ) -> None:
        self._creds     = creds
        self._port      = port
        self._timeout   = timeout
        self._retries   = retries
        # Per-vendor SNMPv3 context overrides. Keyed by vendor string
        # (matches drivers.detector constants):
        #     {'aruba_cx': 'network', 'cisco_ios': '', 'arista_eos': ''}
        # An empty-string value forces the default empty context;
        # absence of a key means "use credentials' default".
        self._per_vendor_context: dict = dict(per_vendor_context or {})
        # Diagnostic tracking. Last reason a .get() returned None.
        # Surfaced by the Settings → SNMPv3 → Test button so the
        # operator can tell pysnmp-missing from auth-failure from
        # timeout from no-such-object.
        #
        # Held in threading.local so concurrent SwitchMonitor threads
        # (one per switch) don't stomp on each other's diagnostic
        # state. The .last_error / .last_detail @properties unwrap it.
        self._tl = threading.local()

    @property
    def last_error(self) -> str:
        return getattr(self._tl, "last_error", "")

    @last_error.setter
    def last_error(self, value: str) -> None:
        self._tl.last_error = value

    @property
    def last_detail(self) -> str:
        return getattr(self._tl, "last_detail", "")

    @last_detail.setter
    def last_detail(self, value: str) -> None:
        self._tl.last_detail = value

    # Hard cap on calls per cached engine. Even when every call
    # succeeds, pysnmp's asyncio dispatcher accumulates a small
    # amount of state per call. Resetting periodically keeps
    # long-running daemons (200 SwitchMonitor threads × multi-day
    # uptime) from bloating into GB of pending-task garbage.
    _ENGINE_MAX_CALLS = 200

    def _get_engine(self):
        """
        Return a per-thread cached SnmpEngine. Caching cuts down
        engine churn (and the resulting "Task was destroyed but it
        is pending!" warnings) but a long-lived engine in a worker
        thread accumulates asyncio dispatcher state, so we rebuild
        every _ENGINE_MAX_CALLS or whenever ``_reset_engine()``
        is called explicitly.
        """
        engine = getattr(self._tl, "engine", None)
        used   = getattr(self._tl, "engine_calls", 0)
        if engine is None or used >= self._ENGINE_MAX_CALLS:
            if engine is not None:
                self._close_engine(engine)
            from pysnmp.hlapi import SnmpEngine
            engine = SnmpEngine()
            self._tl.engine = engine
            used = 0          # we just built a fresh engine — restart counter
        self._tl.engine_calls = used + 1
        return engine

    def _close_engine(self, engine) -> None:
        """Best-effort teardown of an SnmpEngine's transport
        dispatcher so its pending asyncio tasks get a chance to
        cancel cleanly."""
        try:
            engine.transportDispatcher.closeDispatcher()
        except Exception as exc:
            log.debug("SNMP: closeDispatcher raised on teardown: %s", exc)

    def _reset_engine(self) -> None:
        """Discard the current thread's cached engine. Used after a
        failed call, since failures are the primary source of
        pending timeout tasks. Successful calls reuse the engine
        cleanly until the call-count cap above."""
        engine = getattr(self._tl, "engine", None)
        if engine is not None:
            self._close_engine(engine)
            self._tl.engine       = None
            self._tl.engine_calls = 0

    # ─── low-level GET ───────────────────────────────────────────────────────

    def get(
        self,
        host: str,
        oid: str,
        *,
        context_override: Optional[str] = None,
    ) -> Optional[str]:
        """
        SNMPv3 GET. Returns the variable value as a string (whatever
        pysnmp's prettyPrint produces) or None on any failure —
        timeout, auth error, no-such-object, missing pysnmp.

        Designed to never raise: callers can wrap a poll in this and
        treat a None as "device unreachable" without exception
        handling.

        Per-call context override
        -------------------------
        ``context_override`` lets a caller use a different SNMPv3
        context than the credentials' default for this one call.
        Pass an explicit empty string to force the default context;
        leave as None to use the credentials' configured value.

        Why: real fleets mix vendors with different context
        conventions — Aruba CX commonly scopes a user under a named
        context like "network", while Cisco IOS-XE and Arista EOS
        leave the user in the default empty context. The
        SwitchMonitor selects the right context based on the
        previously-detected vendor for each host.
        """
        self.last_error  = ""
        self.last_detail = ""

        # pysnmp's synchronous hlapi runs an asyncio call under the hood.
        # On Python 3.12 worker threads have no default event loop, which
        # causes pysnmp's internal asyncio.get_event_loop() to raise. Make
        # sure this thread has a loop before we hand off to pysnmp.
        _ensure_thread_event_loop()

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
        except ImportError as exc:
            # Distinguish "pysnmp not installed" from "pysnmp 7.x is
            # installed but its synchronous hlapi was removed". Both
            # raise ImportError on the line above; only one of them
            # has a fix that involves "uninstall and reinstall a
            # specific version range."
            try:
                import pysnmp as _pysnmp_pkg     # type: ignore[import]
                installed_version = getattr(_pysnmp_pkg, "__version__",
                                            "unknown")
            except ImportError:
                installed_version = None

            if installed_version is None:
                self.last_error  = "pysnmp_not_installed"
                self.last_detail = (
                    "pysnmp is not installed. On the agent host run: "
                    "sudo pip3 install -r /opt/aruba-agent/requirements.txt"
                )
            else:
                # pysnmp is importable but the synchronous getCmd is gone.
                # The legacy sync API was actually removed in 6.2 (not
                # 7.0 as we first thought) — pin must be < 6.2 to land
                # on a version that still exposes it.
                self.last_error  = "pysnmp_incompatible_version"
                self.last_detail = (
                    f"pysnmp {installed_version} is installed but the "
                    f"synchronous hlapi (getCmd) was removed in 6.2 "
                    f"and later. This agent currently requires pysnmp "
                    f"5.x or 6.0/6.1. Fix:\n"
                    f"  sudo pip3 uninstall -y pysnmp\n"
                    f"  sudo pip3 install 'pysnmp<6.2'\n"
                    f"  sudo systemctl restart aruba-agent"
                )
            log.warning("%s (%s)", self.last_detail, exc)
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
                self.last_error  = "bad_context_engine_id"
                self.last_detail = f"context_engine_id is not valid hex: {exc}"
                log.warning(self.last_detail)
                return None
        # Pick the context: per-call override wins (including empty
        # string), otherwise fall back to the credentials' default.
        effective_context = (
            context_override if context_override is not None
            else self._creds.context_name
        )
        context_data = ContextData(
            contextEngineId=context_engine_id,
            contextName=effective_context,
        )

        try:
            result = getCmd(
                self._get_engine(),
                user_data,
                UdpTransportTarget(
                    (host, self._port),
                    timeout=self._timeout,
                    retries=self._retries,
                ),
                context_data,
                ObjectType(ObjectIdentity(oid)),
            )
            # API shape varies across pysnmp versions:
            #   * pysnmp 5.x:  getCmd returns a generator that yields
            #                  exactly one tuple — caller does next(...)
            #   * pysnmp 6.1.x: getCmd returns the tuple directly
            # Detect at runtime so we work on either.
            if isinstance(result, tuple):
                error_indication, error_status, _err_idx, var_binds = result
            else:
                error_indication, error_status, _err_idx, var_binds = next(result)
        except Exception as exc:
            self.last_error  = "engine_error"
            self.last_detail = f"{type(exc).__name__}: {exc}"
            log.debug("SNMP GET %s on %s raised: %s", oid, host, self.last_detail)
            self._reset_engine()
            return None

        if error_indication:
            txt = str(error_indication)
            # Map common indications to actionable categories so the UI
            # can show a useful hint rather than a raw pysnmp string.
            if "timeout" in txt.lower() or "no SNMP response" in txt:
                self.last_error = "timeout"
            elif "authentication" in txt.lower():
                self.last_error = "auth_failure"
            elif "engineID" in txt or "Unknown SNMP engine" in txt:
                self.last_error = "engine_id_mismatch"
            elif "Unknown USM user" in txt or "user name" in txt.lower():
                self.last_error = "unknown_user"
            elif "decryption" in txt.lower() or "privacy" in txt.lower():
                self.last_error = "privacy_failure"
            else:
                self.last_error = "snmp_error"
            self.last_detail = txt
            log.debug("SNMP GET %s on %s: %s (%s)",
                      oid, host, self.last_error, txt)
            self._reset_engine()
            return None
        if error_status:
            self.last_error  = "pdu_error"
            self.last_detail = error_status.prettyPrint()
            log.debug("SNMP GET %s on %s: PDU error %s",
                      oid, host, self.last_detail)
            self._reset_engine()
            return None
        for _name, val in var_binds:
            return val.prettyPrint()

        self.last_error  = "no_var_binds"
        self.last_detail = "PDU returned no variable bindings"
        self._reset_engine()
        return None

    # ─── high-level helpers ──────────────────────────────────────────────────

    def is_reachable(
        self, host: str, *, context_override: Optional[str] = None,
    ) -> bool:
        """True if sysUpTime.0 came back. The actual value is irrelevant
        for reachability — receiving any response means the SNMP engine
        on the switch is alive and authenticated us successfully."""
        return self.get(host, OID_SYS_UPTIME,
                        context_override=context_override) is not None

    def get_uptime_centiseconds(
        self, host: str, *, context_override: Optional[str] = None,
    ) -> Optional[int]:
        v = self.get(host, OID_SYS_UPTIME, context_override=context_override)
        if v is None:
            return None
        try:
            return int(v)
        except ValueError:
            return None

    def get_sys_name(
        self, host: str, *, context_override: Optional[str] = None,
    ) -> Optional[str]:
        """Configured hostname. Equivalent to AOS-CX /system.hostname,
        Cisco IOS `hostname`, Arista EOS `hostname` config line."""
        return self.get(host, OID_SYS_NAME, context_override=context_override)

    def get_sys_descr(
        self, host: str, *, context_override: Optional[str] = None,
    ) -> Optional[str]:
        """Free-form vendor string — used as fallback when sysObjectID
        doesn't match our known-vendor table."""
        return self.get(host, OID_SYS_DESCR, context_override=context_override)

    def get_sys_object_id(
        self, host: str, *, context_override: Optional[str] = None,
    ) -> Optional[str]:
        """Vendor's enterprise OID under 1.3.6.1.4.1.<n>. C3's vendor
        detector keys off this."""
        return self.get(host, OID_SYS_OBJECT_ID,
                        context_override=context_override)

    # ─── per-vendor context selection ────────────────────────────────────────

    def context_for_vendor(self, vendor: Optional[str]) -> Optional[str]:
        """
        Return the right context_override to pass to .get() for a
        host of the given detected vendor.

        * Vendor string maps to a configured override → return it.
          (Empty string is a valid value — it forces the empty
          default context.)
        * Vendor unknown / blank → return None, which means "use
          the credentials' default context_name" — usually right
          for the Aruba-heavy first-poll case.
        """
        if not vendor:
            return None
        return self._per_vendor_context.get(vendor)


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

    # Per-vendor context overrides. Operators with a mixed Aruba +
    # Cisco + Arista fleet typically need different contexts per
    # vendor — Aruba CX often uses a named context like 'network'
    # while Cisco IOS-XE / Arista EOS leave the user in the default
    # empty context. Each key is optional; missing keys mean
    # "use the credentials' default context_name".
    per_vendor_ctx: dict = {}
    for vendor_key, cfg_key in (
        ("aruba_cx",    "context_name_aruba_cx"),
        ("cisco_ios",   "context_name_cisco_ios"),
        ("arista_eos",  "context_name_arista_eos"),
        ("aruba_os",    "context_name_aruba_os"),
    ):
        if cfg_key in s:
            # Note: we DO want to honor an explicit empty value here,
            # because '' is the SNMPv3 default context and meaningful.
            per_vendor_ctx[vendor_key] = s.get(cfg_key, "").strip()

    return SnmpAgent(
        creds              = creds,
        port               = int(s.get("port",    "161")),
        timeout            = int(s.get("timeout", "2")),
        retries            = int(s.get("retries", "1")),
        per_vendor_context = per_vendor_ctx,
    )
