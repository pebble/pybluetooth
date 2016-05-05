from enum import Enum
from scapy.layers.bluetooth import *
from scapy.utils import mac2str, str2mac


class AddressType(Enum):
    public = 0
    random = 1


class Address(object):
    @staticmethod
    def from_packet(packet):
        if packet.getlayer(HCI_LE_Meta_Connection_Complete) is not None:
            return Address(packet.paddr, packet.patype)
        if packet.getlayer(HCI_LE_Meta_Advertising_Report) is not None:
            return Address(packet.addr, packet.atype)
        raise Exception("No mapping to Address for packet %s" % packet)

    def __init__(self, bd_addr, address_type=AddressType.random):
        if isinstance(address_type, int):
            address_type = AddressType(address_type)
        assert isinstance(bd_addr, str)
        assert len(bd_addr) >= 6
        if len(bd_addr) > 6:
            bd_addr = mac2str(bd_addr)
            assert len(bd_addr) == 6

        self.bd_addr = bd_addr
        self.address_type = address_type

    def __eq__(self, other):
        return (
            isinstance(other, Address) and
            self.bd_addr == other.bd_addr and
            self.address_type == other.address_type)

    def is_random(self):
        return self.address_type == AddressType.random

    def is_public(self):
        return self.address_type == AddressType.public

    def macstr(self):
        return str2mac(self.bd_addr)

    def __str__(self):
        return "{} {}, address_type={}".format(
            super(Address, self).__str__(), str2mac(self.bd_addr),
            self.address_type)
