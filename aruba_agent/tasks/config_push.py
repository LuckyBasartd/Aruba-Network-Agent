"""
Batch CLI config push — multi-vendor, over SSH via netmiko.

Pushes a set of CLI config commands to a list of switches of a SINGLE
vendor, concurrently, and (always, per operator policy) saves the
running config to startup on success. Returns a per-device result so
the UI can show exactly what happened where.

Why netmiko directly instead of the existing drivers: the Aruba driver
speaks REST and the Cisco/Arista drivers speak NAPALM — neither is a
natural fit for pushing arbitrary CLI *config*. netmiko gives one
uniform SSH config-mode path across all three vendors
(``aruba_aoscx`` / ``cisco_ios`` / ``arista_eos``).

netmiko is imported lazily so the agent still starts if it's absent
(it ships transitively with napalm); a missing netmiko simply turns
every push into a clear per-device error rather than crashing startup.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

log = logging.getLogger(__name__)

# SwitchState.vendor  ->  netmiko device_type
NETMIKO_DEVICE_TYPE: Dict[str, str] = {
    "aruba_cx":   "aruba_aoscx",
    "aruba_os":   "aruba_aoscx",   # tolerate either label for AOS-CX
    "cisco_ios":  "cisco_ios",
    "arista_eos": "arista_eos",
}


def parse_commands(text: str) -> List[str]:
    """Split a pasted command block into individual lines, dropping
    blank lines. Preserves order and (intentional) indentation."""
    out: List[str] = []
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if line.strip():
            out.append(line)
    return out


def _save_config(net, vendor: str) -> str:
    """Persist running-config to startup. Tries netmiko's save_config()
    first; falls back to an explicit vendor command (AOS-CX's
    save_config isn't always implemented in netmiko)."""
    try:
        return net.save_config()
    except Exception:                                  # noqa: BLE001
        cmd = "write memory" if vendor in ("aruba_cx", "aruba_os") \
            else "copy running-config startup-config"
        try:
            return net.send_command_timing(cmd)
        except Exception as exc:                       # noqa: BLE001
            raise RuntimeError(f"save-to-startup failed: {exc}") from exc


def _push_one(target: dict, device_type: str, vendor: str,
              commands: List[str], creds: dict, save: bool,
              conn_timeout: int, read_timeout: int) -> dict:
    from netmiko import ConnectHandler                 # lazy

    name = target.get("name") or target.get("host")
    host = target.get("host")
    result = {"name": name, "host": host, "ok": False,
              "output": "", "error": "", "duration": 0.0}
    started = time.monotonic()

    params = {
        "device_type":   device_type,
        "host":          host,
        "username":      creds.get("username", ""),
        "password":      creds.get("password", ""),
        "fast_cli":      False,
        "conn_timeout":  conn_timeout,
        "auth_timeout":  conn_timeout,
        "banner_timeout": conn_timeout,
    }
    if creds.get("secret"):
        params["secret"] = creds["secret"]

    net = None
    try:
        net = ConnectHandler(**params)
        # Cisco privileged exec if an enable secret is configured.
        if creds.get("secret") and vendor == "cisco_ios":
            net.enable()
        out = net.send_config_set(commands, read_timeout=read_timeout)
        if save:
            out += "\n" + _save_config(net, vendor)
        result["ok"] = True
        result["output"] = out
    except Exception as exc:                           # noqa: BLE001
        # netmiko raises several exception types (timeout, auth, ssh);
        # a single message per device is what the operator needs.
        result["error"] = f"{type(exc).__name__}: {exc}"
        log.warning("Config push failed on %s (%s): %s", name, host, exc)
    finally:
        if net is not None:
            try:
                net.disconnect()
            except Exception:                          # noqa: BLE001
                pass
        result["duration"] = round(time.monotonic() - started, 1)
    return result


def push_to_switches(targets: List[dict], vendor: str, commands: str,
                     creds: dict, *, save: bool = True, max_workers: int = 5,
                     conn_timeout: int = 30, read_timeout: int = 60) -> List[dict]:
    """
    Push ``commands`` to every host in ``targets`` (all of ``vendor``),
    concurrently. ``targets`` is a list of ``{"name","host"}``. ``creds``
    is ``{"username","password","secret"(optional)}``. Returns a list of
    per-device result dicts (same order not guaranteed; each carries its
    name/host).
    """
    device_type = NETMIKO_DEVICE_TYPE.get(vendor)
    cmd_list = parse_commands(commands)

    if device_type is None:
        return [{"name": t.get("name") or t.get("host"), "host": t.get("host"),
                 "ok": False, "output": "",
                 "error": f"unsupported vendor: {vendor}", "duration": 0.0}
                for t in targets]
    if not cmd_list:
        return [{"name": t.get("name") or t.get("host"), "host": t.get("host"),
                 "ok": False, "output": "", "error": "no commands to send",
                 "duration": 0.0} for t in targets]

    # Guard the whole thing so a missing netmiko degrades to clear errors.
    try:
        import netmiko  # noqa: F401
    except Exception as exc:                           # noqa: BLE001
        return [{"name": t.get("name") or t.get("host"), "host": t.get("host"),
                 "ok": False, "output": "",
                 "error": f"netmiko unavailable: {exc}", "duration": 0.0}
                for t in targets]

    results: List[dict] = []
    workers = max(1, min(max_workers, len(targets) or 1))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cfgpush") as pool:
        futs = [pool.submit(_push_one, t, device_type, vendor, cmd_list,
                            creds, save, conn_timeout, read_timeout)
                for t in targets]
        for fut in as_completed(futs):
            results.append(fut.result())

    ok = sum(1 for r in results if r["ok"])
    log.info("Config push to %d %s switch(es): %d ok, %d failed",
             len(targets), vendor, ok, len(results) - ok)
    return results
