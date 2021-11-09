import netifaces
from scapy.all import *
import socket

from .utils import get_interface_info

class CaptureMgr:

  def __init__(self, capture_int=None):

    print(60*"*" + " Configure a capture interface:")
    self.interface_cap = get_interface_info(capture_int)
    self.hostname = socket.gethostname()
    
    print(f"{self.hostname}: {self.interface_cap}")

  def capture(self, count=None):
    sniff(iface=self.interface_cap['name'], count=count, prn=lambda x: x.summary())