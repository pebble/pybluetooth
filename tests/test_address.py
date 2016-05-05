import binascii

from scapy.layers.bluetooth import *
from scapy.utils import mac2str, str2mac
from pybluetooth.address import *


def test_address_from_hci_le_connection_complete_packet():
    raw_data = binascii.unhexlify(
        "043e1301004800000110c8b8a5eac9380000002a0000")
    packet = HCI_Hdr(raw_data)

    address = Address.from_packet(packet)
    assert str2mac(address.bd_addr) == "c9:ea:a5:b8:c8:10"
    assert address.macstr() == "c9:ea:a5:b8:c8:10"
    assert address.address_type == AddressType.random
    assert address.is_random()
    assert not address.is_public()

def test_address_from_advertising_report_packet():
    raw_data = binascii.unhexlify(
        "043e280201000110c8b8a5eac91c0201060303d9fe"
        "1109506562626c652054696d652043383130020a00d5")
    packet = HCI_Hdr(raw_data)

    address = Address.from_packet(packet)
    assert str2mac(address.bd_addr) == "c9:ea:a5:b8:c8:10"
    assert address.macstr() == "c9:ea:a5:b8:c8:10"
    assert address.address_type == AddressType.random
    assert address.is_random()
    assert not address.is_public()

