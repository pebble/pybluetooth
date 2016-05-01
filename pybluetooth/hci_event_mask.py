import struct


""" From Core v4.2, Vol 2, Part E, 7.3.1 Set Event Mask Command """
HCIEventMaskValues = {
    0x0000000000000001: "Inquiry Complete Event",
    0x0000000000000002: "Inquiry Result Event",
    0x0000000000000004: "Connection Complete Event",
    0x0000000000000008: "Connection Request Event",
    0x0000000000000010: "Disconnection Complete Event",
    0x0000000000000020: "Authentication Complete Event",
    0x0000000000000040: "Remote Name Request Complete Event",
    0x0000000000000080: "Encryption Change Event",
    0x0000000000000100: "Change Connection Link Key Complete Event",
    0x0000000000000200: "Master Link Key Complete Event",
    0x0000000000000400: "Read Remote Supported Features Complete Event",
    0x0000000000000800: "Read Remote Version Information Complete Event",
    0x0000000000001000: "QoS Setup Complete Event",
    0x0000000000002000: "Reserved",
    0x0000000000004000: "Reserved",
    0x0000000000008000: "Hardware Error Event",
    0x0000000000010000: "Flush Occurred Event",
    0x0000000000020000: "Role Change Event",
    0x0000000000040000: "Reserved",
    0x0000000000080000: "Mode Change Event",
    0x0000000000100000: "Return Link Keys Event",
    0x0000000000200000: "PIN Code Request Event",
    0x0000000000400000: "Link Key Request Event",
    0x0000000000800000: "Link Key Notification Event",
    0x0000000001000000: "Loopback Command Event",
    0x0000000002000000: "Data Buffer Overflow Event",
    0x0000000004000000: "Max Slots Change Event",
    0x0000000008000000: "Read Clock Offset Complete Event",
    0x0000000010000000: "Connection Packet Type Changed Event",
    0x0000000020000000: "QoS Violation Event",
    0x0000000040000000: "Page Scan Mode Change Event [deprecated]",
    0x0000000080000000: "Page Scan Repetition Mode Change Event",
    0x0000000100000000: "Flow Specification Complete Event",
    0x0000000200000000: "Inquiry Result with RSSI Event",
    0x0000000400000000: "Read Remote Extended Features Complete Event",
    0x0000000800000000: "Reserved",
    0x0000001000000000: "Reserved",
    0x0000002000000000: "Reserved",
    0x0000004000000000: "Reserved",
    0x0000008000000000: "Reserved",
    0x0000010000000000: "Reserved",
    0x0000020000000000: "Reserved",
    0x0000040000000000: "Reserved",
    0x0000080000000000: "Synchronous Connection Complete Event",
    0x0000100000000000: "Synchronous Connection Changed Event",
    0x0000200000000000: "Sniff Subrating Event",
    0x0000400000000000: "Extended Inquiry Result Event",
    0x0000800000000000: "Encryption Key Refresh Complete Event",
    0x0001000000000000: "IO Capability Request Event",
    0x0002000000000000: "IO Capability Request Reply Event",
    0x0004000000000000: "User Confirmation Request Event",
    0x0008000000000000: "User Passkey Request Event",
    0x0010000000000000: "Remote OOB Data Request Event",
    0x0020000000000000: "Simple Pairing Complete Event",
    0x0040000000000000: "Reserved",
    0x0080000000000000: "Link Supervision Timeout Changed Event",
    0x0100000000000000: "Enhanced Flush Complete Event",
    0x0200000000000000: "Reserved",
    0x0400000000000000: "User Passkey Notification Event",
    0x0800000000000000: "Keypress Notification Event",
    0x1000000000000000: "Remote Host Supported Features Notification Event",
    0x2000000000000000: "LE Meta-Event",
    0xC000000000000000: "Reserved",
}


def to_little_endian_bytes(v):
    return struct.pack("<Q", v)


def all_enabled():
    mask = 0
    for k in HCIEventMaskValues:
        if HCIEventMaskValues[k] != "Reserved":
            mask |= k
    return mask


def all_reserved():
    mask = 0
    for k in HCIEventMaskValues:
        if HCIEventMaskValues[k] == "Reserved":
            mask |= k
    return mask


def all_enabled_str():
    return to_little_endian_bytes(all_enabled())


def all_reserved_str():
    return to_little_endian_bytes(all_reserved())


if __name__ == '__main__':
    import binascii
    print "all_enabled: 0x%x" % all_enabled()
    print "all_enabled_str: %s" % binascii.hexlify(all_enabled_str())
