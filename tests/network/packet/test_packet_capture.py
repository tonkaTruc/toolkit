import pytest
from scapy.layers.l2 import Ether

from tests import log
from ttk.network.packet.capture import PackerCaptor


@pytest.fixture
def packet_captor() -> PackerCaptor:
    return PackerCaptor(capture_int="en1")


def test_packet_captor_init(packet_captor):
    assert isinstance(packet_captor, PackerCaptor)
    assert packet_captor.interface == "en1"


def test_packet_captor_print_live_traffic(packet_captor):
    log.info(f"Printing 20 packets of live traffic on {packet_captor.interface}")
    pkts = packet_captor.capture_traffic(
        count=20,
        cb=lambda pkt: log.warning(pkt.summary())
    )
    assert len(pkts) == 20
    for pkt in pkts:
        assert isinstance(pkt, Ether)
