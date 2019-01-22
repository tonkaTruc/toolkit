import threading, socket, struct, os, array
from scapy.all import ETH_P_ALL
from scapy.all import select
from scapy.all import MTU


class PacketSniffer(threading.Thread):

    def __init__(self, interface, ip_incoming, ip_outgoing):
        super().__init__(group=None, target=None, name=None, daemon=None)

        self._return = []

        self.interface_name = interface
        self.ip_incoming = ip_incoming
        self.ip_outgoing = ip_outgoing

        # Create a raw L2 ingress socket and bind to specified interface
        self.ingress_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.ingress_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.ingress_sock.bind((self.interface_name, ETH_P_ALL))

    def join(self, timeout=None):
        threading.Thread.join(self)
        return self._return

    def __process_ipframe(self, pkt_type, ip_header, payload):

        # Extract 20 bytes IP header
        fields = struct.pack("!BBHHHBBHII", ip_header)

        dummy_hdrlen = fields[0] & 0xf
        iplen = fields[2]

        ip_src = payload[12:16]
        ip_dst = payload[16:20]
        ip_frame = payload[0:iplen]

        if pkt_type == socket.PACKET_OUTGOING:
            if self.ip_outgoing is not None:
                self.ip_outgoing(ip_src, ip_dst, ip_frame)

        else:
            if self.ip_incoming is not None:
                self.ip_incoming(ip_src, ip_dst, ip_frame)

    def recv(self):
        while True:

            pkt, sa_11 = self.ingress_sock.recvfrom(MTU)

            if type == socket.PACKET_OUTGOING and self.ip_outgoing is None:
                continue
            elif self.ip_incoming is None:
                continue

            if len(pkt) <= 0:
                break

            eth_header = struct.unpack("!6s6sH", pkt[0:14])

            dummy_eth_proto = socket.ntohs(eth_header[2])

            if eth_header[2] != 0x800:
                continue

            ip_header = pkt[14:34]
            payload = pkt[14:]

            self.__process_ipframe(sa_11[2], ip_header, payload)


    def run(self):

        ip_sniff.recv


if __name__ == "__main__":

    thread_count = 1
    i = 0
    threads = []

    def incoming(src, dst, frame):
        print("incoming - src: %s \tdst: %s \tframe len: %d" % socket.inet_ntoa(src), socket.inet_ntoa(dst),
              len(frame))


    def outgoing(src, dst, frame):
        print("outgoing - src: %s \tdst: %s \tframe len: %d" % socket.inet_ntoa(src), socket.inet_ntoa(dst),
              len(frame))

    while i is not thread_count:
        threaded_sniffer = PacketSniffer("enp0s3", incoming, outgoing)
        threads.append(threaded_sniffer)
        i += 1

    for thread in threads:
        print("Starting threaded packet sniffer: %s" % thread)
        thread.start()

    for thread in threads:
        print("Allowing threaded packet sniffer to join: %s" % thread)
        thread.join()



