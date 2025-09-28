import logging
import socket

from scapy.all import sniff

from ttk.network.interfaces import get_best_interface_for


class CaptureMgr:

    def __init__(self, capture_int=None):
        self.log = logging.getLogger("__name__")
        self.log.info(60*"*" + " Configure a capture interface:")
        self.interface_cap = get_best_interface_for(capture_int)
        self.hostname = socket.gethostname()
        self.log.info(f"{self.hostname}: {self.interface_cap}")

    def capture(self, count=None):
        sniff(
            iface=self.interface_cap['name'],
            count=count,
            prn=lambda x: x.summary()
        )
