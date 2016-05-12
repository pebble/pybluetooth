from pybluetooth.address import *
from pybluetooth.sm import *

def test_c1():
    # Example from BT Spec v4.2, Vol 3, Part H, 2.2.3
    k = "00000000000000000000000000000000".decode("hex")
    rand = "5783D52156AD6F0E6388274EC6702EE0".decode("hex")
    expected_result = "1e1e3fef878988ead2a74dc5bef13b86".decode("hex")
    request_cmd = "07071000000101".decode("hex")
    response_cmd = "05000800000302".decode("hex")

    initiating_address = Address("A1:A2:A3:A4:A5:A6",
                                 address_type=AddressType.random)
    responding_address = Address("B1:B2:B3:B4:B5:B6",
                                 address_type=AddressType.public)

    result = c1(k, rand, request_cmd, response_cmd,
                initiating_address, responding_address)

    assert(result == expected_result)

def test_s1():
    # Example from BT Spec v4.2, Vol 3, Part H, 2.2.4
    r1 = "000F0E0D0C0B0A091122334455667788".decode("hex")
    r2 = "010203040506070899AABBCCDDEEFF00".decode("hex")
    k = "00000000000000000000000000000000".decode("hex")
    expected_result = "9a1fe1f0e8b0f49b5b4216ae796da062".decode("hex")

    result = s1(k, r1, r2)

    assert(result == expected_result)
