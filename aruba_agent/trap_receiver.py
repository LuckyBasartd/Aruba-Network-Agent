"""
SNMP trap receiver — listens for v2c/v3 traps, classifies, stores, and alerts.

Two halves:
  * ``handle_trap()`` — pure-ish: given a parsed trap (source IP, snmpTrapOID,
    varbinds) it classifies (traps.py), maps the source to a known switch,
    persists to the store, and emails on *critical* traps (rate-limited). No
    pysnmp — fully unit-testable with a fake store/notifier.
  * ``TrapReceiver.start()`` — the pysnmp transport shell: a Notification
    receiver bound to UDP 162 running its own asyncio dispatcher in a daemon
    thread. Imported lazily and wrapped so a pysnmp/permission problem logs and
    disables traps rather than crashing the agent.

Privileged port: UDP 162 needs root or CAP_NET_BIND_SERVICE. Run as non-root by
granting the venv python the capability, or set [traps] port to a high port and
redirect 162 -> it. See TROUBLESHOOTING.md.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from aruba_agent import traps

log = logging.getLogger(__name__)

OID_SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"   # snmpTrapOID.0
OID_SYS_UPTIME    = "1.3.6.1.2.1.1.3.0"


class TrapReceiver:
    def __init__(self, cfg, state, store, notifier) -> None:
        t = cfg["traps"] if "traps" in cfg else {}
        self.state = state
        self.store = store
        self.notifier = notifier

        self.enabled       = (t.get("enabled", "false") or "false").lower() == "true"
        self.bind_address  = t.get("bind_address", "0.0.0.0") or "0.0.0.0"
        self.port          = int(t.get("port", "162") or "162")
        self.communities   = _csv(t.get("communities", t.get("community", "public")))
        self.alert_policy   = (t.get("alert_policy", "critical") or "critical").strip().lower()
        # suppress duplicate alerts for the same (switch, trap) within a window
        self.alert_dedup_s  = int(t.get("alert_dedup_seconds", "300") or "300")
        # which SNMP profiles to accept v3 traps from (reuse polling creds)
        self.v3_profiles    = _csv(t.get("v3_profiles", ""))

        self._cfg = cfg
        self._engine = None
        self._thread = None
        self._recent: Dict[Tuple[str, str], float] = {}
        self._lock = threading.Lock()
        self._v3_users: list = []        # [(user, authProto, authKey, privProto, privKey)]
        self._learned_engines: set = set()   # engine IDs we've registered users for

    # ── host → switch name ──────────────────────────────────────────────────────

    def _host_to_switch(self, ip: str) -> str:
        try:
            for sw in self.state.switches.values():
                if getattr(sw, "host", None) == ip:
                    return sw.name
        except Exception:
            pass
        return ip

    # ── the testable core ───────────────────────────────────────────────────────

    def handle_trap(self, source_ip: str, trap_oid: str,
                    varbinds: Optional[List[Tuple[str, str]]] = None,
                    name_hint: str = "") -> dict:
        """Classify, persist, and (if critical) alert on one trap. Returns the
        stored doc. Never raises."""
        varbinds = varbinds or []
        rec = traps.classify_trap(trap_oid, varbinds, name_hint=name_hint)
        switch = self._host_to_switch(source_ip)
        # resolve ifName for link traps if we can
        port_label = rec.get("ifindex")
        message = self._summarize(rec, switch, varbinds)
        doc = {
            "ts":        datetime.now(timezone.utc),
            "source_ip": source_ip,
            "switch":    switch,
            "oid":       rec["oid"],
            "name":      rec["name"],
            "category":  rec["category"],
            "severity":  rec["severity"],
            "ifindex":   rec.get("ifindex"),
            "varbinds":  [{"oid": o, "value": str(v)} for o, v in varbinds],
            "message":   message,
        }
        try:
            self.store.save_trap(doc)
        except Exception as exc:
            log.error("trap: save failed (%s)", exc)

        alerted = False
        if traps.should_alert(rec, self.alert_policy) and self._rate_ok(switch, rec["name"]):
            alerted = True
            subj = f"[Network Agent] {rec['severity'].upper()} trap: {rec['name']} on {switch}"
            try:
                self.notifier.send(subj, message)
            except Exception as exc:
                log.error("trap: alert email failed (%s)", exc)
        log.info("trap: %s from %s (%s) severity=%s%s",
                 rec["name"], source_ip, switch, rec["severity"],
                 " -> ALERT emailed" if alerted else "")
        return doc

    def _summarize(self, rec: dict, switch: str, varbinds) -> str:
        parts = [f"{rec['severity'].upper()} {rec['name']} ({rec['category']})",
                 f"switch: {switch}", f"trapOID: {rec['oid']}"]
        if rec.get("ifindex"):
            parts.append(f"ifIndex: {rec['ifindex']}")
        if varbinds:
            parts.append("varbinds:")
            for o, v in varbinds[:12]:
                parts.append(f"  {o} = {v}")
        return "\n".join(parts)

    def _rate_ok(self, switch: str, name: str) -> bool:
        """True if we haven't emailed this (switch, trap) within the dedup
        window — stops a flapping component from spamming."""
        now = time.time()
        key = (switch, name)
        with self._lock:
            last = self._recent.get(key, 0.0)
            if now - last < self.alert_dedup_s:
                return False
            self._recent[key] = now
            # opportunistic prune
            if len(self._recent) > 5000:
                cutoff = now - self.alert_dedup_s
                self._recent = {k: v for k, v in self._recent.items() if v >= cutoff}
        return True

    # ── pysnmp transport shell (not unit-tested; guarded) ───────────────────────

    def start(self) -> bool:
        if not self.enabled:
            return False
        try:
            self._thread = threading.Thread(target=self._serve, name="trap-receiver",
                                            daemon=True)
            self._thread.start()
            log.info("Trap receiver starting on %s:%d (v2c communities=%d, v3 profiles=%d, policy=%s)",
                     self.bind_address, self.port, len(self.communities),
                     len(self.v3_profiles), self.alert_policy)
            return True
        except Exception as exc:
            log.error("Trap receiver failed to start: %s", exc)
            return False

    def stop(self) -> None:
        eng = self._engine
        if eng is None:
            return
        try:
            eng.transportDispatcher.jobFinished(1)
        except Exception:
            pass
        try:
            eng.transportDispatcher.closeDispatcher()
        except Exception:
            pass

    def _serve(self) -> None:
        try:
            import asyncio
            asyncio.set_event_loop(asyncio.new_event_loop())
            from pysnmp.entity import engine, config
            from pysnmp.carrier.asyncio.dgram import udp
            from pysnmp.entity.rfc3413 import ntfrcv
        except Exception as exc:
            log.error("Trap receiver: pysnmp trap API unavailable (%s) — traps disabled", exc)
            return

        # pysnmp's asyncio openServerMode binds lazily on the loop, so a
        # PermissionError on a privileged port is swallowed and the "listening"
        # log lies. Pre-bind a plain socket to surface the real error up front.
        import socket as _sock
        try:
            _t = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            _t.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
            _t.bind((self.bind_address, self.port))
            _t.close()
        except PermissionError:
            log.error("Trap receiver: permission denied binding UDP %d "
                      "(privileged port). Grant CAP_NET_BIND_SERVICE via a "
                      "systemd AmbientCapabilities override, or set a high "
                      "[traps] port (e.g. 16200) + an iptables 162->port "
                      "redirect. Traps DISABLED.", self.port)
            return
        except OSError as exc:
            log.error("Trap receiver: cannot bind %s:%d (%s). Traps DISABLED.",
                      self.bind_address, self.port, exc)
            return

        try:
            snmp_engine = engine.SnmpEngine()
            self._engine = snmp_engine
            try:
                config.addTransport(
                    snmp_engine, udp.domainName,
                    udp.UdpTransport().openServerMode((self.bind_address, self.port)))
            except Exception as exc:
                log.error("Trap receiver: cannot bind %s:%d (%s).",
                          self.bind_address, self.port, exc)
                return

            # v2c communities
            for i, comm in enumerate(self.communities):
                if comm:
                    config.addV1System(snmp_engine, f"area-{i}", comm)

            # v3 users from the named SNMP profiles (reuse polling creds).
            # Register for the local engine now, and learn each switch's
            # remote engine ID from its first (failed) trap via the observer.
            self._build_v3_users()
            self._register_v3_users(snmp_engine, config)
            try:
                snmp_engine.observer.registerObserver(
                    self._v3_learn, 'rfc3412.prepareDataElements:sm-failure')
            except Exception as exc:
                log.warning('Trap receiver: could not register v3 learn observer (%s)', exc)

            ntfrcv.NotificationReceiver(snmp_engine, self._cb)
            snmp_engine.transportDispatcher.jobStarted(1)
            log.info("Trap receiver listening on %s:%d", self.bind_address, self.port)
            try:
                snmp_engine.transportDispatcher.runDispatcher()
            except Exception:
                snmp_engine.transportDispatcher.closeDispatcher()
                raise
        except Exception as exc:
            log.error("Trap receiver crashed: %s", exc)

    def _build_v3_users(self) -> None:
        """Resolve [traps] v3_profiles into concrete USM user specs (decrypted)."""
        self._v3_users = []
        if not self.v3_profiles:
            return
        try:
            from aruba_agent.snmp_profiles import from_config
            from pysnmp.entity import config as _c
            reg = from_config(self._cfg)
            auth_map = {"MD5": _c.usmHMACMD5AuthProtocol, "SHA": _c.usmHMACSHAAuthProtocol,
                        "SHA256": _c.usmHMAC192SHA256AuthProtocol,
                        "SHA512": _c.usmHMAC384SHA512AuthProtocol,
                        "NONE": _c.usmNoAuthProtocol}
            priv_map = {"DES": _c.usmDESPrivProtocol, "AES128": _c.usmAesCfb128Protocol,
                        "AES256": _c.usmAesCfb256Protocol, "NONE": _c.usmNoPrivProtocol}
        except Exception as exc:
            log.warning("Trap receiver: could not prepare v3 users (%s)", exc)
            return
        for pname in self.v3_profiles:
            prof = reg.get(pname)
            if prof is None:
                continue
            c = prof.creds
            self._v3_users.append((
                c.username,
                auth_map.get((c.auth_protocol or "SHA").upper(), auth_map["SHA"]),
                c.auth_password or "",
                priv_map.get((c.priv_protocol or "AES128").upper(), priv_map["AES128"]),
                c.priv_password or "",
            ))

    def _register_v3_users(self, snmp_engine, config, security_engine_id=None) -> int:
        """Register all resolved v3 users, optionally bound to a specific
        (remote) securityEngineId. Returns how many were added."""
        n = 0
        for (user, authp, authk, privp, privk) in self._v3_users:
            try:
                if security_engine_id is not None:
                    config.addV3User(snmp_engine, user, authp, authk, privp, privk,
                                     securityEngineId=security_engine_id)
                else:
                    config.addV3User(snmp_engine, user, authp, authk, privp, privk)
                n += 1
            except Exception as exc:
                log.debug("Trap receiver: addV3User(%s) failed (%s)", user, exc)
        return n

    def _v3_learn(self, snmp_engine, execpoint, variables, cbCtx) -> None:
        """pysnmp observer: on a security failure (typically UnknownSecurityName
        because a v3 trap carries the *sender's* engine ID, which we can't know
        in advance), learn that engine ID and register our v3 user(s) against
        it so subsequent traps from that switch authenticate. Runs in the
        dispatcher thread, so addV3User here is thread-safe."""
        try:
            eid = variables.get("securityEngineId") or variables.get("contextEngineId")
            if eid is None:
                si = variables.get("statusInformation")
                if isinstance(si, dict):
                    eid = si.get("contextEngineId") or si.get("securityEngineId")
            if eid is None:
                return
            key = bytes(eid)
            if not key or key in self._learned_engines:
                return
            self._learned_engines.add(key)
            from pysnmp.entity import config as _c
            added = self._register_v3_users(snmp_engine, _c, security_engine_id=eid)
            pretty = eid.prettyPrint() if hasattr(eid, "prettyPrint") else key.hex()
            log.info("Trap receiver: learned v3 engine %s — registered %d user(s); "
                     "subsequent traps from it will authenticate", pretty, added)
        except Exception as exc:
            log.debug("Trap receiver: v3 learn observer error: %s", exc)

    def _cb(self, snmp_engine, state_ref, ctx_engine_id, ctx_name, var_binds, cb_ctx):
        """pysnmp NotificationReceiver callback. Extract source + varbinds and
        hand off to handle_trap. Never raise back into the dispatcher."""
        try:
            source_ip = "?"
            try:
                td, ta = snmp_engine.msgAndPduDsp.getTransportInfo(state_ref)
                source_ip = ta[0]
            except Exception:
                pass
            pairs: List[Tuple[str, str]] = []
            trap_oid = ""
            for name, val in var_binds:
                oid = str(name)
                sval = val.prettyPrint() if hasattr(val, "prettyPrint") else str(val)
                if oid == OID_SNMP_TRAP_OID:
                    trap_oid = sval.strip()
                    continue
                if oid == OID_SYS_UPTIME:
                    continue
                pairs.append((oid, sval))
            self.handle_trap(source_ip, trap_oid, pairs)
        except Exception as exc:
            log.error("trap callback error: %s", exc)


def _csv(v: str) -> List[str]:
    return [x.strip() for x in (v or "").replace(" ", ",").split(",") if x.strip()]
