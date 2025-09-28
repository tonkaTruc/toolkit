import os

from invoke.tasks import task

from ttk.network.interfaces import create_interfaces_dict
from ttk.network.packet.capture import PackerCaptor

# from ttk.network.multicast import MulticastMgr
# from ttk.network.server import SimpleServer


@task
def list_interfaces(c):
    """List available network interfaces on this host"""

    for iface, info in create_interfaces_dict().items():
        print(f"{iface}: {[x['address'] for x in info['addresses']]}")


@task
def print_traffic(c, interface=None, count=20):
    """Capture network traffic on a specified interface"""

    if os.geteuid() != 0:
        print("Warning: This task requires root to access network interfaces.")
        return

    print(f"Capturing {count} packets on {interface}")
    open_hole = PackerCaptor(capture_int=interface)
    pkts = open_hole.capture_traffic(count=count)

    for pkt in pkts:
        print(pkt.summary())


# @task
# def multicast_join(c, addr):
#     """Send a multicast group join request and loop forever"""

#     # Assign a manager by supplying the IP of the target switch device
#     mgr = MulticastMgr(switch_ip="192.168.0.1")
#     mgr.join(addr)

#     try:
#         print(f"Multicast JOIN has been sent for {addr}")
#         while True:
#             pass
#     except KeyboardInterrupt:
#         mgr.leave(addr)


# @task
# def server_local_serve(c, port):
#     """ Serves a basic connection point to localhost on a given port"""
#     SimpleServer("127.0.0.1", port).serve()
