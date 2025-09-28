import logging
import re
import socket
import struct
import sys

from .utils import get_best_interface_for


class MulticastMgr:

    def __init__(self, switch_ip: str):

        self.log = logging.getLogger("__name__")
        self.local_ip = get_best_interface_for(switch_ip)
        self.sock = create_socket(self.local_ip, 9989)
        self.log.info(f"Using interface: {self.local_ip}:{self.sock}")

        # Set multicast interface to local_ip
        self.sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_IF,
            socket.inet_aton(self.local_ip)
        )

        # Set multicast time-to-live to 2...
        # keep our multicast packets from escaping the local network
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    def join(self, multicast_ip):
        """Construct a membership request and send to socket to join a
        multicast group"""

        mreq = struct.pack(
            "4sl",
            socket.inet_aton(multicast_ip),
            socket.INADDR_ANY
        )
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    def leave(self, multicast_ip):
        """Construct a membership request and send to socket to leave a
        multicast group"""

        mreq = struct.pack(
            "4sl",
            socket.inet_aton(multicast_ip),
            socket.INADDR_ANY
        )
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)

    def display_traffic(self):
        while True:
            print(self.sock.recv(1))


def create_socket(ip: str, port: int) -> socket.socket:
    """An open socket bound to the specified ip and port.

    Args:
        ip (str): IP address to bind
        port (int): Port to bind

    Returns:
        socket.socket: The created socket
    """

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Allow reuse of addresses
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # If you bind to a specific interface on the Mac, no multicast data.
    # If you try to bind to all interfaces on Windows, no multicast data.
    # Hence we check if running on macos before binding the socket.
    # TODO: system detection should be handled at a higher level
    is_macos = sys.platform.startswith("darwin") is True
    sock.bind(('0.0.0.0', port)) if is_macos else sock.bind((ip, port))
    return sock


def ip_is_local(ip_string) -> bool:
    """Uses a regex to determine if the input ip is on a local network.

    It's safe here, but never use a regex for IP verification if from
    a potentially dangerous source.
    """
    # If the regex matches then the ip is likely to be a local ip
    local_ip = "(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)"
    return re.match(local_ip, ip_string) is not None


def print_stream_info(socket):

    # Data waits on socket buffer until we retrieve it.
    # TODO: filter it out traffic if it came from the current machine.

    # Test Var
    multicast_ip = "239.1.2.3"

    packet = socket.recvfrom(2624)

    # packet tuple to string
    packet = packet[0]

    # Take first 20 characters as IP header
    ip_header = packet[0:20]

    iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    protocol = iph[6]

    u = iph_length
    udph_length = 8
    udp_header = packet[u:u+udph_length]

    # now unpack them :)
    udph = struct.unpack('!HHHH' , udp_header)

    source_port = udph[0]
    dest_port = udph[1]

    if protocol == 17:
        protocol = 'UDP'

    src_addr = socket.inet_ntoa(iph[8])
    dst_addr = socket.inet_ntoa(iph[9])

    if dst_addr == multicast_ip:
        print('\nMulticast stream detected!')
        print('\nProtocol: \t\t', protocol)
        print('Source Port: \t\t', source_port, '\nDestination Port: \t', dest_port)
        print('Source Address: \t', src_addr, '\nDestination Address: \t', dst_addr)
        print('\nCheck wireshark to ensure the correct packets are reaching your NIC\n')
        return True

    else:
        print('No Multicast stream present at: ', multicast_ip)
        return False
