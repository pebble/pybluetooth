from pybluetooth import hci_event_mask


def test_hci_event_mask_all_enabled():
    m = hci_event_mask.all_enabled()
    assert(m == 0x3dbff807fffb9fff)

    m_bytes = hci_event_mask.all_enabled_str()
    assert(m_bytes == "\xff\x9f\xfb\xff\x07\xf8\xbf\x3d")


def test_hci_event_mask_to_little_endian_bytes():
    m_bytes = hci_event_mask.to_little_endian_bytes(0)
    assert(m_bytes == "\x00\x00\x00\x00\x00\x00\x00\x00")

    m_bytes = hci_event_mask.to_little_endian_bytes(
        0x1122334455667788)
    assert(m_bytes == "\x88\x77\x66\x55\x44\x33\x22\x11")
