from time import sleep

import pytest


@pytest.mark.parametrize("addr", ["239.0.0.1", "239.1.23.4"])
def multicast_join(mcast_client, addr):
    """Send a multicast group join request and loop forever"""

    mcast_client.join(addr)
    print(f"Multicast JOIN has been sent for {addr}")
    sleep(5)
    mcast_client.leave(addr)
