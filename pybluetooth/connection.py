import logging

from enum import Enum
from pybluetooth.address import *
from pybluetooth.exceptions import *
from pybluetooth.hci_errors import *
from scapy.layers.bluetooth import *
from threading import Event, RLock


LOG = logging.getLogger("pybluetooth")


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
    def __init__(self, intended=True):
        self.role = Role.none
        self._state = State.disconnected
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

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, new_state):
        self._state = new_state
        if new_state == State.connected:
            self.connected_event.set()
            self.disconnected_event.clear()
        elif new_state == State.disconnecting:
            self.connected_event.clear()
            self.disconnected_event.clear()
        else:  # initiating / disconnected
            self.connected_event.clear()
            self.disconnected_event.set()

    def wait_until_connected(self, timeout=None):
        if not self.connected_event.wait(timeout):
            raise TimeoutException

    def wait_until_disconnected(self, timeout=None):
        if not self.disconnected_event.wait(timeout):
            raise TimeoutException

    def __str__(self):
        addr_str = None
        if self.address:
            addr_str = str2mac(self.address.bd_addr)
        return "{} address={}, state={}".format(
            super(Connection, self).__str__(), addr_str, self.state)


class ConnectionManager(object):
    def __init__(self, hci_thread, cb_thread):
        self.connections = set()
        self.hci = hci_thread
        self.cb_thread = cb_thread
        self.is_initiating = False
        self.lock = RLock()

        def _is_le_connection_event_filter(packet):
            return packet.getlayer(HCI_LE_Meta_Connection_Complete) is not None
        self.cb_thread.add_callback(
            _is_le_connection_event_filter, self.handle_connection_packet)

        def _is_disconnection_event_filter(packet):
            return packet.getlayer(HCI_Event_Disconnection_Complete) is not None
        self.cb_thread.add_callback(
            _is_disconnection_event_filter, self.handle_disconnection_packet)

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
                    connection = Connection(intended=False)
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

            connection = Connection(intended=True)
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
