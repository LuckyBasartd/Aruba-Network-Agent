"""
Vendor drivers — one module per switch vendor, all sharing the
SwitchDriver protocol from drivers.base.

Public surface:

    from aruba_agent.drivers import driver_for, SwitchDriver
    from aruba_agent.drivers.base import ArpEntry, Facts

    with driver_for(host, user, pw) as drv:
        if drv.is_reachable():
            cfg = drv.get_running_config()
"""

from aruba_agent.drivers.base    import ArpEntry, Facts, SwitchDriver
from aruba_agent.drivers.factory import driver_for

__all__ = ["ArpEntry", "Facts", "SwitchDriver", "driver_for"]
