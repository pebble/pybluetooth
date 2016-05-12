import logging

from Crypto import Random
from Crypto.Cipher import AES
from enum import IntEnum
from pybluetooth.address import *
from pybluetooth.connection import *
from pybluetooth.exceptions import *
from scapy.layers.bluetooth import *


LOG = logging.getLogger("pybluetooth")


AES_BLOCK_SIZE = 16


class SMPairingErrorReason(IntEnum):
    reserved_00 = 0x00
    passkey_entry_failed = 0x01
    oob_not_available = 0x02
    authentication_requirements = 0x03
    confirm_value_failed = 0x04
    pairing_not_supported = 0x05
    encryption_key_size = 0x06
    command_not_supported = 0x07
    unspecified_reason = 0x08
    repeated_attempts = 0x09
    invalid_parameters = 0x0A
    dhkey_check_failed = 0x0B
    numeric_comparison_failed = 0x0C
    br_edr_pairing_in_progress = 0x0D
    cross_transport_key_derivation_generation_now_allowed = 0x0E


class SMIOCapabilities(IntEnum):
    display_only = 0x0
    display_yes_no = 0x1
    keyboard_only = 0x2
    no_input_no_output = 0x3
    keyboard_display = 0x4


class SMAuthenticationReqFlag(IntEnum):
    no_bonding = 0x0
    bonding = 0x1
    mitm = 0x4
    sc = 0x8
    keypress = 0x10


class SMKeyDistributionFlag(IntEnum):
    enc_key = 0x1
    id_key = 0x2
    sign_key = 0x4
    link_key = 0x8


class SMPairingType(Enum):
    legacy_just_works = 1
    legacy_passkey_entry = 2
    legacy_out_of_band = 3
    secure_connections = 4


class SMPairingState(Enum):
    idle = 0
    awaiting_pairing_response = 1
    awaiting_legacy_pairing_confirm = 2
    awaiting_legacy_pairing_random = 3
    awaiting_link_encryption = 4
    awaiting_key_distribution = 5


def xor_str(a_str, b_str):
    return "".join(map(lambda a, b: chr(ord(a) ^ ord(b)), a_str, b_str))


def e(key, plain_text):
    return AES.new(key).encrypt(plain_text)


def c1(tk, rand, request_cmd, response_cmd,
       initiating_address, responding_address):
    """ Confirm value generation function c1 for LE Legacy Pairing
        See BT Spec v4.2, Vol 3, Part H, 2.2.3.
    """
    assert isinstance(initiating_address, Address)
    assert isinstance(responding_address, Address)
    assert len(tk) == AES_BLOCK_SIZE
    assert len(rand) == AES_BLOCK_SIZE
    assert len(request_cmd) == 7
    assert len(response_cmd) == 7

    def type_byte_from_addr(address):
        return "\x01" if address.is_random() else "\x00"

    p1 = (response_cmd + request_cmd +
          type_byte_from_addr(responding_address) +
          type_byte_from_addr(initiating_address))

    padding = "\x00" * 4
    p2 = padding + initiating_address.bd_addr + responding_address.bd_addr

    x1 = xor_str(rand, p1)
    e1 = e(tk, x1)
    x2 = xor_str(e1, p2)
    return e(tk, x2)


def s1(tk, srand, mrand):
    """ Key generation function s1 for LE Legacy Pairing
        See BT Spec v4.2, Vol 3, Part H, 2.2.4.
    """
    assert len(tk) == AES_BLOCK_SIZE
    assert len(srand) == AES_BLOCK_SIZE
    assert len(mrand) == AES_BLOCK_SIZE

    r = srand[8:] + mrand[8:]
    return e(tk, r)


class SecurityManager(object):
    def __init__(self, connection):
        self.connection = connection
        self.state = SMPairingState.idle
        self.request_cmd = None
        self.response_cmd = None
        self.mrand = None
        self.srand = None
        self.remote_confirm = None
        self.tk = None

    def cleanup(self):
        self.state = SMPairingState.idle
        self.request_cmd = None
        self.response_cmd = None
        self.mrand = None
        self.srand = None
        self.remote_confirm = None
        self.tk = None

    def send(self, sm_packet):
        self.connection.send(SM_Hdr() / sm_packet)

    def pair(self):
        if self.state != SMPairingState.idle:
            raise AlreadyInProgressException("Pairing is already in progress")
        self.state = SMPairingState.awaiting_pairing_response
        dist = SMKeyDistributionFlag.enc_key | \
               SMKeyDistributionFlag.id_key | \
               SMKeyDistributionFlag.sign_key
        request = SM_Pairing_Request(
            iocap=SMIOCapabilities.keyboard_display,
            authentication=SMAuthenticationReqFlag.bonding,
            initiator_key_distribution=dist,
            responder_key_distribution=dist,
        )
        # Save the request + SMP header, we need it to calculate the confirm
        # value later on.
        self.request_cmd = SM_Hdr() / request
        self.send(request)

    def start_encryption(self):
        stk = s1(self.tk, self.srand, self.mrand)
        random = "\x00" * 8
        ediv = 0
        self.connection.start_encryption(random, ediv, stk)

    def calculate_confirm(self, random):
        def reversed_bytes_from_cmd(cmd):
            return str(cmd[SM_Hdr])[::-1]
        return c1(self.tk, random,
                  reversed_bytes_from_cmd(self.request_cmd),
                  reversed_bytes_from_cmd(self.response_cmd),
                  self.connection.own_address, self.connection.address)

    def _initiating_send_confirm(self):
        self.mrand = Random.get_random_bytes(AES_BLOCK_SIZE)
        mconfirm = self.calculate_confirm(self.mrand)
        reversed_mconfirm = mconfirm[::-1]
        self.state = SMPairingState.awaiting_legacy_pairing_confirm
        self.send(SM_Confirm(confirm=reversed_mconfirm))

    def _initiating_send_confirm_just_works(self):
        self.tk = "\x00" * 16
        self._initiating_send_confirm()

    def _initiating_send_mrand(self):
        self.state = SMPairingState.awaiting_legacy_pairing_random
        reversed_mrand = self.mrand[::-1]
        self.send(SM_Random(random=reversed_mrand))

    def _verify_confirm(self, random_data):
        expected_sconfirm = self.calculate_confirm(random_data)
        if expected_sconfirm != self.remote_confirm:
            LOG.error("Pairing Confirm mismatch!")
            self.send(SM_Failed(
                reason=SMPairingErrorReason.confirm_value_failed))
            self.cleanup()
        else:
            self.start_encryption()

    def handle_sm_packet(self, packet):
        if packet.getlayer(SM_Failed):
            LOG.error(
                "Pairing failed with reason %s" %
                SMPairingErrorReason(packet.reason))
            self.cleanup()
            return
        if packet.getlayer(SM_Pairing_Request):
            raise NotYetImplementedException("Pairing as slave is NYI")
        if packet.getlayer(SM_Pairing_Response):
            # TODO: Look at the IO capabilities and pick the right pairing
            # method. For now, just assume "Just Works".
            if self.state == SMPairingState.awaiting_pairing_response:
                self.response_cmd = packet
                self._initiating_send_confirm_just_works()
                return
        if packet.getlayer(SM_Confirm):
            if self.state == SMPairingState.awaiting_legacy_pairing_confirm:
                self.remote_confirm = packet.confirm[::-1]
                self._initiating_send_mrand()
                return
        if packet.getlayer(SM_Random):
            if self.state == SMPairingState.awaiting_legacy_pairing_random:
                self.srand = packet.random[::-1]
                self._verify_confirm(self.srand)
                return
        LOG.debug("Got unhandled SM packet in state %s:" % self.state)
        packet.show()

        # TODO: Send appropriate failure response and update our state

    def handle_connected(self):
        pass

    def handle_disconnected(self):
        pass

