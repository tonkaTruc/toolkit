import socket
from typing import Dict

import psutil

ADDR_FAMILY_MAP = {
    socket.AF_INET: "IPv4",
    socket.AF_INET6: "IPv6",
}

# AF_PACKET (Linux) or AF_LINK (macOS/BSD)
if hasattr(socket, "AF_PACKET"):
    ADDR_FAMILY_MAP[socket.AF_PACKET] = "MAC"
if hasattr(socket, "AF_LINK"):
    ADDR_FAMILY_MAP[socket.AF_LINK] = "MAC"


def create_interfaces_dict() -> Dict[str, Dict]:
    """Generate a dict of available network interfaces on this host.

    Returns:
        Dict: Information for all available host network interfaces
    """

    interfaces = {}
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface, addr_list in addrs.items():
        iface_data = {
            "addresses": [],
            "is_up": stats[iface].isup if iface in stats else None,
            "speed_mbps": stats[iface].speed if iface in stats else None,
            "mtu": stats[iface].mtu if iface in stats else None,
        }

        for addr in addr_list:
            iface_data["addresses"].append({
                "family": ADDR_FAMILY_MAP.get(addr.family, "-1"),
                "address": addr.address,
                "netmask": addr.netmask,
                "broadcast": addr.broadcast,
                "ptp": addr.ptp,
            })

        interfaces[iface] = iface_data

    return interfaces
