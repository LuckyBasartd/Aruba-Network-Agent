"""
Vendor-neutral switch driver interface.

A SwitchDriver represents a logical session against a single switch.
Implementations live in sibling modules (aruba_cx.py, cisco_ios.py,
arista_eos.py). All implementations honor the same lifecycle:

    drv = SomeDriver(host, user, pw, ...)
    drv.login()                  # establish session (or no-op for stateless)
    drv.is_reachable()           # cheap health check
    drv.get_facts()              # hostname / vendor / model / os version
    drv.get_running_config()     # bytes — full running-config text
    drv.save_running_to_startup()# write mem
    drv.get_arp_table()          # list[ArpEntry]
    drv.cli("show whatever")     # raw text — vendor-specific commands
    drv.logout()                 # tear down session

Drivers MUST be usable as context managers (login on enter, logout on
exit). Driver implementations MUST NOT raise on transport errors —
return None / [] / False and set self.error so callers can decide.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Protocol, runtime_checkable


# ─── data classes ─────────────────────────────────────────────────────────────

@dataclass
class ArpEntry:
    """One row from a switch's ARP table."""
    ip:        str
    mac:       str
    interface: str = ""    # e.g. "1/1/1" or "GigabitEthernet1/0/1"
    vlan:      str = ""    # e.g. "vlan100"
    age:       str = ""    # vendor-formatted age string


@dataclass
class Facts:
    """
    Coarse-grained device identification. Filled in best-effort —
    a field may be empty if the vendor doesn't surface it cheaply.
    """
    hostname:   str = ""
    vendor:     str = ""    # "aruba_cx" | "cisco_ios" | "arista_eos" | ...
    model:      str = ""    # e.g. "6300M" / "C9300-48P" / "DCS-7050SX"
    os_version: str = ""    # e.g. "10.13.1150" / "16.12.4" / "4.30.1F"
    serial:     str = ""


# ─── protocol ────────────────────────────────────────────────────────────────

@runtime_checkable
class SwitchDriver(Protocol):
    """
    The contract every vendor driver implements. Treat as duck-typing
    rather than strict subclassing — concrete drivers don't need to
    inherit from this Protocol, only match its surface.
    """

    # Identity
    host:       str
    vendor:     str            # populated by the implementation
    error:      str            # last error message (empty when fine)
    logged_in:  bool           # True after a successful login()

    # Lifecycle
    def login(self) -> bool: ...
    def logout(self) -> None: ...
    def __enter__(self) -> "SwitchDriver": ...
    def __exit__(self, exc_type, exc, tb) -> None: ...

    # Health
    def is_reachable(self) -> bool: ...

    # Identity / facts
    def get_hostname(self) -> Optional[str]: ...
    def get_facts(self) -> Optional[Facts]: ...

    # Configuration
    def get_running_config(self) -> Optional[bytes]: ...
    def save_running_to_startup(self) -> bool: ...

    # Operational
    def cli(self, cmd: str) -> Optional[str]:
        """
        Run a 'show ...' command and return raw text output. Vendor
        commands differ — callers should know what they're asking
        for, or use the higher-level helpers below.
        """
        ...

    def get_arp_table(self) -> List[ArpEntry]:
        """Parsed ARP table. Empty list on failure."""
        ...
