from scapy.layers.l2 import Ether
from scapy.all import IP, UDP, send
from scapy.packet import Packet, bind_layers
from scapy.fields import *

# IP header
src_addr = "192.168.0.125" # PTP GM
dst_addr = "192.168.10.200" # Qx

# UDP header
udp_src_port = 320
udp_dst_port = 320

# PTP packet constituion info taken from: https://support.huawei.com/hedex/pages/EDOC100010596830008125/05/EDOC100010596830008125/05/resources/message/cd_feature_1588v2_format-general.html


class ieee1588(Packet):
    name = "Precision Time Protocol"

    fields_desc = [
        BitField('transportSpecific', 1, 4),        # 4 bits
        BitField('messageType', 0, 4),              # 4 bits
        BitField('versionPTP', 2, 4),               # 4 bits
        LenField('messageLength', 0, fmt="H"),      # 2 bytes (what is fmt=H)
        ByteField('subdomainNumber', 0),
        ByteField('dummy1', 0),
        XShortField('flags', 0),                    # 2 bytes
        LongField('correction', 0),                 # 64 bits
        IntField('dummy2', 0),
        XLongField('ClockIdentity', 0),
        XShortField('SourcePortId', 0),
        XShortField('sequenceId', 0),               # 2 bytes
        ByteField('control', 0),                    # 1 byte
        SignedByteField('logMessagePeriod', 0),     # 1 byte
        Field('TimestampSec', 0, fmt='6s'),
        IntField('TimestampNanoSec', 0)
    ]


bind_layers(Ether, ieee1588, type="0x88F7")

#pkt = Ether() / IP(src=src_addr, dst=dst_addr) / UDP(sport=udp_src_port, dport=udp_dst_port)  #/ ieee1588()

#print(pkt.show())

#send(pkt)
