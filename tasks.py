from invoke import run, task

from Toolkit.capture import CaptureMgr
from Toolkit.multicast import MulticastMgr
from Toolkit.server import SimpleServer


@task
def multicast_join(c, addr):
    """Send a multicast group join request and loop forever"""

    # Assign a manager by supplying the IP of the target switch device
    mgr = MulticastMgr(switch_ip="192.168.0.1")
    mgr.join(addr)

    try:
        print(f"Multicast JOIN has been sent for {addr}")
        while True:
            pass
    except KeyboardInterrupt:
        mgr.leave(addr)


@task
def server_local_serve(c, port):
    """ Serves a basic connection point to localhost on a given port"""
    SimpleServer("127.0.0.1", port).serve()


@task
def capture(c, interface=None, count=20):
    """Capture network traffic on a specified interface"""

    cap = CaptureMgr(capture_int=interface)
    try:
        cap.capture(count=count)
    except KeyboardInterrupt:
        quit()
