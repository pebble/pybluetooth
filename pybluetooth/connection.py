import logging

from enum import Enum
from pybluetooth.address import *
from pybluetooth.exceptions import *
from pybluetooth.hci_errors import *
from pybluetooth.sm import *
from scapy.layers.bluetooth import *
from threading import Event, RLock


LOG = logging.getLogger("pybluetooth")


class L2CAPFixedChannelID(Enum):
    signaling = 1
    connectionless = 2
    amp = 3
    att = 4
    le_signaling = 5
    security_manager = 6


class Role(Enum):
    none = -1
    master = 0
    slave = 1


class State(Enum):
    initiating = 0
    connected = 1
    disconnecting = 2
    disconnected = 3


class Connection(object):
    def __init__(self, hci_thread, l2cap_thread, own_address, intended=True):
        self.role = Role.none
        self._state = State.disconnected
        self.hci_thread = hci_thread
        self.l2cap_thread = l2cap_thread
        self.own_address = own_address
        # Indicates the host wants to be connected to this device (may not be
        # true when local device is slave).
        self.intended = intended
        self.address = None
        self.connected_event = Event()
        self.disconnected_event = Event()
        self.disconnected_event.set()
        self.handle = 0
        self.interval_ms = 0
        self.slave_latency = 0
        self.supervision_timeout = 0
        self.sm = SecurityManager(self)

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, new_state):
        self._state = new_state
        if new_state == State.connected:
            self.connected_event.set()
            self.disconnected_event.clear()
            self.sm.handle_connected()
        elif new_state == State.disconnecting:
            self.connected_event.clear()
            self.disconnected_event.clear()
        else:  # initiating / disconnected
            self.sm.handle_disconnected()
            self.connected_event.clear()
            self.disconnected_event.set()

    def wait_until_connected(self, timeout=None):
        if not self.connected_event.wait(timeout):
            raise TimeoutException

    def wait_until_disconnected(self, timeout=None):
        if not self.disconnected_event.wait(timeout):
            raise TimeoutException

    def handle_l2cap_packet(self, packet):
        if L2CAPFixedChannelID(packet.cid) == \
                L2CAPFixedChannelID.security_manager:
            self.sm.handle_sm_packet(packet)
        else:
            LOG.debug(
                "NYI: packet on %s channel!" % L2CAPFixedChannelID(packet.cid))

    def send(self, l2cap_payload):
        self.l2cap_thread.send(self.handle, l2cap_payload)

    def start_encryption(self, random, ediv, stk):
        self.hci_thread.cmd_le_start_encryption(self.handle, random, ediv, stk)

    def handle_encryption_change(self, is_enabled):
        self.sm.handle_encryption_change(is_enabled)

    def __str__(self):
        addr_str = None
        if self.address:
            addr_str = str2mac(self.address.bd_addr)
        return "{} address={}, state={}".format(
            super(Connection, self).__str__(), addr_str, self.state)


class ConnectionManager(object):
    def __init__(self, hci_thread, l2cap_thread, cb_thread):
        self.connections = set()
        self.hci = hci_thread
        self.l2cap_thread = l2cap_thread
        self.cb_thread = cb_thread
        self.is_initiating = False
        self.lock = RLock()
        self.own_public_address = None

        def _is_le_connection_event_filter(packet):
            return packet.getlayer(HCI_LE_Meta_Connection_Complete) is not None
        self.cb_thread.add_callback(
            _is_le_connection_event_filter, self.handle_connection_packet)

        def _is_disconnection_event_filter(packet):
            return packet.getlayer(HCI_Event_Disconnection_Complete) is not None
        self.cb_thread.add_callback(
            _is_disconnection_event_filter, self.handle_disconnection_packet)

        def _is_encryption_change_event_filter(packet):
            return packet.getlayer(HCI_Event_Encryption_Change) is not None
        self.cb_thread.add_callback(
            _is_encryption_change_event_filter, self.handle_encryption_change_packet)

        def _is_l2cap_event_filter(packet):
            return packet.getlayer(HCI_ACL_Hdr) is not None
        self.cb_thread.add_callback(
            _is_l2cap_event_filter, self.handle_l2cap_packet)

    def find_connection_by_filter_assert_unique(self, filter_func):
        matches = filter(filter_func, self.connections)
        assert len(matches) <= 1
        if len(matches) == 1:
            return matches[0]
        return None

    def find_connection_by_address(self, address):
        return self.find_connection_by_filter_assert_unique(
            lambda c: c.address == address)

    def find_connection_by_handle(self, handle):
        return self.find_connection_by_filter_assert_unique(
            lambda c: c.handle == handle)

    def handle_l2cap_packet(self, packet):
        # scapy has a couple shortcomings: the packet boundary field in
        # HCI_ACL_Hdr isn't parsed correctly. It also doesn't seem to support
        # the case where an ACL packet does not contain a complete L2CAP packet.
        # So in case we get a non-complete packet, raise an exception:
        if packet.flags != 32:
            raise NotYetImplementedException("")
        connection = self.find_connection_by_handle(packet.handle)
        connection.handle_l2cap_packet(packet)

    def handle_connection_packet(self, packet):
        self.is_initiating = False
        status = HCIErrorCode(packet.status)
        if status == HCIErrorCode.success:
            LOG.debug("Connection complete to %s success" % packet.paddr)
            address = Address.from_packet(packet)
            with self.lock:
                connection = self.find_connection_by_address(address)
                if not connection:
                    LOG.debug("No intended connection found")
                    connection = Connection(self.hci,
                                            self.l2cap_thread,
                                            self.own_public_address,
                                            intended=False)
                    self.connections.add(connection)
                connection.handle = packet.handle
                connection.address = address
                connection.interval_ms = packet.interval * 1.25
                connection.slave_latency = packet.latency
                connection.supervision_timeout = packet.supervision * 10
                connection.role = Role(packet.role)
                connection.state = State.connected
        elif status == HCIErrorCode.unknown_connection_id:
            # Eat this. It happens after "LE Create Connection Cancel".
            pass
        else:
            LOG.debug("Connection complete error: %u (NYI)" % packet.status)

    def handle_disconnection_packet(self, packet):
        with self.lock:
            connection = self.find_connection_by_handle(packet.handle)
            assert connection
            LOG.debug(
                "Disconnection Complete to %s, status=0x%x, reason=0x%x" %
                (connection.address.macstr(), packet.status, packet.reason))
            connection.state = State.disconnected
            if not connection.intended:
                self.connections.remove(connection)
            else:
                LOG.debug("NYI: Auto-reconnecting isn't implemented yet.")
                self.connections.remove(connection)

    def handle_encryption_change_packet(self, packet):
        connection = None
        with self.lock:
            connection = self.find_connection_by_handle(packet.handle)
        connection.handle_encryption_change(packet.enabled > 0)

    def connect(self, address):
        with self.lock:
            connection = self.find_connection_by_address(address)
            if connection:
                LOG.debug("Already initiating connection to %s" % address)
                return connection

            if self.is_initiating:
                # TODO: Use BT controller's white list
                raise NotYetImplementedException(
                    "Having multiple outstanding connect() calls is NYI...")

            self.is_initiating = True
            self.hci.cmd_le_create_connection(address)

            connection = Connection(self.hci,
                                    self.l2cap_thread,
                                    self.own_public_address,
                                    intended=True)
            connection.address = address
            connection.state = State.initiating
            self.connections.add(connection)
            return connection

    def disconnect(self, connection):
        with self.lock:
            if connection.state == State.initiating:
                assert self.is_initiating
                LOG.debug("Cancelling connecting to %s" % connection.address)
                self.hci.cmd_le_connection_create_cancel()
                # Simplify things a bit. A Connection Complete event with
                # reason 0x02 "Unknown Connection Identifier" indicates
                # cancellation was successful. Don't wait for it and and flip
                # the flag now:
                self.is_initiating = False
                connection.state = State.disconnected
                self.connections.remove(connection)
            elif connection.state == State.connected:
                LOG.debug("Disconnecting %s" % connection.address)
                self.hci.cmd_disconnect(connection.handle)
                connection.intended = False
                connection.state = State.disconnecting
