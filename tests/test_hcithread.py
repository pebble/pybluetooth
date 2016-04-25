from pybluetooth import HCIThread
from pybluetooth.address import *

from scapy.layers.bluetooth import *

try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock


def _create_patched_hci_thread():
    h = HCIThread(MagicMock())
    h.sent_packets = []

    def send_cmd(scapy_packet, *args, **kwargs):
        h.sent_packets.append(scapy_packet)
    h.send_cmd = send_cmd
    return h


def test_hci_thread_cmd_le_create_connection():
    h = _create_patched_hci_thread()
    a = Address("c9:ea:a5:b8:c8:1", AddressType.random)
    h.cmd_le_create_connection(a)
    p = h.sent_packets[0]
    assert p.getlayer(HCI_Cmd_LE_Create_Connection)
    assert p.patype == 0x01  # Random
    assert p.paddr == "c9:ea:a5:b8:c8:01"
