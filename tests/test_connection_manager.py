import binascii
import pytest

from pybluetooth.address import *
from pybluetooth.connection import ConnectionManager, Role, State
from pybluetooth.exceptions import *
from pybluetooth import CallbackThread
from scapy.layers.bluetooth import *

try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock


def _connection_complete_event_packet():
    le_conn_complete_raw_data = binascii.unhexlify(
        "043e1301004800000110c8b8a5eac9380000002a0000")
    le_conn_complete_packet = HCI_Hdr(le_conn_complete_raw_data)
    return le_conn_complete_packet


def _disconnection_complete_event_packet():
    disconn_complete_raw_data = binascii.unhexlify("04050400480016")
    return HCI_Hdr(disconn_complete_raw_data)


def test_connection_manager_connect_as_master_successful():
    hci_thread = MagicMock()
    l2cap_thread = MagicMock()
    cb_thread = CallbackThread()
    mgr = ConnectionManager(hci_thread, l2cap_thread, cb_thread)

    address = Address("c9:ea:a5:b8:c8:10", AddressType.random)

    assert mgr.find_connection_by_address(address) is None
    connection = mgr.connect(address)
    assert connection is not None
    hci_thread.cmd_le_create_connection.assert_called_once_with(address)

    connection1 = mgr.connect(address)
    assert connection1 == connection

    connection2 = mgr.find_connection_by_address(address)
    assert connection2 == connection

    assert connection.state == State.initiating
    assert not connection.connected_event.is_set()
    assert connection.disconnected_event.is_set()
    with pytest.raises(TimeoutException):
        connection.wait_until_connected(0)
    connection.wait_until_disconnected(0)

    cb_thread.dispatch_packet(_connection_complete_event_packet())

    assert connection.state == State.connected
    assert connection.connected_event.is_set()
    connection.wait_until_connected(0)
    with pytest.raises(TimeoutException):
        connection.wait_until_disconnected(0)
    assert connection.handle == 72
    assert connection.role == Role.master
    assert connection.interval_ms == 70
    assert connection.slave_latency == 0
    assert connection.supervision_timeout == 420
    assert len(mgr.connections) == 1

    mgr.disconnect(connection)
    assert connection.state == State.disconnecting
    assert not connection.connected_event.is_set()
    assert not connection.disconnected_event.is_set()
    assert len(mgr.connections) == 1

    cb_thread.dispatch_packet(_disconnection_complete_event_packet())

    assert connection.state == State.disconnected
    assert connection.disconnected_event.is_set()
    connection.wait_until_disconnected(0)
    assert len(mgr.connections) == 0


def test_connection_manager_disconnection_event():
    pass
