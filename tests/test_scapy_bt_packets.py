import binascii
import scapy

from scapy.layers.bluetooth import *
from scapy.packet import Packet


scapy.config.conf.debug_dissector = 1


def test_hci_advertising_report_event_ad_data():
    raw_data = binascii.unhexlify(
        "043e2b020100016522c00181781f0201020303d9fe1409"
        "506562626c652054696d65204c452037314536020a0cde")
    packet = HCI_Hdr(raw_data)

    assert(packet[EIR_Flags].flags == 0x02)
    assert(packet[EIR_CompleteList16BitServiceUUIDs].svc_uuids == [0xfed9])
    assert(packet[EIR_CompleteLocalName].local_name == 'Pebble Time LE 71E6')
    assert(packet[EIR_TX_Power_Level].level == 12)


def test_hci_advertising_report_event_scan_resp():
    raw_data = binascii.unhexlify(
        "043e2302010401be5e0eb9f04f1716ff5401005f423331"
        "3134374432343631fc00030c0000de")
    packet = HCI_Hdr(raw_data)

    raw_mfg_data = '\x00_B31147D2461\xfc\x00\x03\x0c\x00\x00'
    assert(packet[EIR_Manufacturer_Specific_Data].data == raw_mfg_data)
    assert(packet[EIR_Manufacturer_Specific_Data].company_id == 0x154)
