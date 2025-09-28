import logging
import socket
from typing import Callable

from scapy.all import PacketList, sniff
from scapy.error import Scapy_Exception


class PackerCaptor:

    def __init__(self, capture_int=None):
        self.log = logging.getLogger("__name__")
        self.interface = capture_int
        self.hostname = socket.gethostname()
        self.log.info(f"{self.hostname}: {self.interface}")

    def capture_traffic(self, count=15, cb: None | Callable = None) -> PacketList:
        """Capture and print live traffic on the specified interface

        Args:
            count (_type_, optional): Number of packets to capture. Defaults to 15.
            cb (Callable, optional): Optional callback function to process each packet.

        Returns:
            PacketList: List of captured packets
        """

        try:
            p_list = sniff(
                iface=self.interface,
                count=count,
                prn=lambda pkt: pkt.summary() if cb is None else cb(pkt),
            )
        except Scapy_Exception as err:
            self.log.error(err)
            raise

        return p_list
