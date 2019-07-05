from scapy.layers.l2 import Ether
from scapy.all import IP, UDP, send
from scapy.packet import Packet, bind_layers
from scapy.fields import *
from custom_headers.erspan import *

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
        XBitField('transportSpecific', 0x1, 4),        # 4 bits
	XBitField('messageType', 0x3, 4),              # 4 bits
        XByteField('versionPTP', 0x05),               # 4 bits
        XShortField('messageLength', 0x0036),      # 2 bytes (what is fmt=H)
        XByteField('subdomainNumber', 0x00),
        XByteField('dummy1', 0x00),
        XShortField('flags', 0x0208),                    # 2 bytes
        XBitField('correction', 0x00000000, 64),                 # 64 bits
        XBitField('dummy2', 0x00, 32),
        XBitField('ClockIdentity', 0x08028efffe9b97a5, 64),
        XShortField('SourcePortId', 0x0002),
        XShortField('sequenceId', 0x0566),               # 2 bytes
        XByteField('control', 0x05),                    # 1 byte
        XByteField('logMessagePeriod', 0x7F),     # 1 byte
        XBitField('requestTimestampSec', 0x00000000057b, 48),
        XBitField('requestTimestampNanoSec', 0x0d11715c, 32),
	XBitField('sourcePortId', 0x08028efffe9b97a5, 64),
	XShortField('requestingSourcePortId', 0x002)
    ]


bind_layers(ERSPAN_III, ieee1588, type="0x88F7")
bind_layers(ERSPAN_III, Ether, type="0x22f0")
#bind_layers(ieee1722, iec61883)

#pkt = Ether() / IP(src=src_addr, dst=dst_addr) / UDP(sport=udp_src_port, dport=udp_dst_port)  #/ ieee1588()

#print(pkt.show())

#send(pkt)
