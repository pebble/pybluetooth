import binascii
import logging
import Queue
from scapy.layers.bluetooth import *
from threading import Event, RLock, Thread

import hci_event_mask
import pyusb_bt_sockets
from connection import ConnectionManager

LOG = logging.getLogger("pybluetooth")


class HCIResponseTimeoutException(Exception):
    pass


class KillableThread(Thread):
    def __init__(self):
        super(KillableThread, self).__init__()
        self.daemon = True
        self.is_killed = Event()

    def run_loop(self):
        raise Exception("Unimplemented")

    def run(self):
        while not self.is_killed.is_set():
            self.run_loop()

    def kill(self):
        self.is_killed.set()


class CallbackThread(KillableThread):
    """ Thread that executes callbacks on behalf various subsystems to process
        and act upon received packets. """
    def __init__(self):
        super(CallbackThread, self).__init__()
        self.packet_queue = Queue.Queue()
        self.lock = RLock()
        self.callbacks = dict()

    def callbacks_filtered_by_packet(self, packet):
        matching_callbacks = []
        with self.lock:
            for callback in self.callbacks:
                packet_filter = self.callbacks[callback]
                if packet_filter(packet):
                    matching_callbacks.append(callback)
        return matching_callbacks

    def has_callback_for_packet(self, packet):
        return len(self.callbacks_filtered_by_packet(packet)) > 0

    def register_with_rx_thread(self, rx_thread):
        rx_thread.add_packet_queue(
            self.has_callback_for_packet, self.packet_queue)

    def add_callback(self, packet_filter, callback):
        with self.lock:
            self.callbacks[callback] = packet_filter

    def remove_packet_queue(self, callback):
        with self.lock:
            del self.callbacks[callback]

    def dispatch_packet(self, packet):
        matching_callbacks = self.callbacks_filtered_by_packet(packet)
        for callback in matching_callbacks:
            callback(packet)

    def run_loop(self):
        try:
            packet = self.packet_queue.get(block=True, timeout=0.1)
        except Queue.Empty:
            return  # Nothing to receive, loop again
        self.dispatch_packet(packet)


class RxThread(KillableThread):
    def __init__(self, socket):
        super(RxThread, self).__init__()
        self.socket = socket
        self.lock = RLock()
        self.packet_queues = dict()

    def run_loop(self):
        packet = self.socket.recv(timeout_secs=0.1)
        if packet is None:
            return  # Nothing to receive, loop again
        matching_queues = self.queues_filtered_by_packet(packet)
        if not matching_queues:
            LOG.warn(
                "Dropping packet, no handler queue!\n%s" % packet.show())
        for queue in matching_queues:
            queue.put(packet)

    def queues_filtered_by_packet(self, packet):
        matching_queues = []
        with self.lock:
            for queue in self.packet_queues:
                packet_filter = self.packet_queues[queue]
                if packet_filter(packet):
                    matching_queues.append(queue)
        return matching_queues

    def add_packet_queue(self, packet_filter, queue):
        """ packet_filter takes a Packet and returns True if it should be added
            to the queue, or False if it should not be added to the queue.
        """
        with self.lock:
            self.packet_queues[queue] = packet_filter

    def remove_packet_queue(self, queue):
        with self.lock:
            del self.packet_queues[queue]


def _create_response_filter(packet_type):
    def _create_hci_response_packet_filter(request_packet):
        opcode = request_packet.overload_fields[HCI_Command_Hdr]['opcode']

        def _hci_cmd_complete_packet_filter(packet):
            if not packet.getlayer(packet_type):
                return False
            return packet.opcode == opcode

        return _hci_cmd_complete_packet_filter

    return _create_hci_response_packet_filter


def _create_hci_cmd_complete_packet_filter():
    return _create_response_filter(HCI_Event_Command_Complete)


def _create_hci_cmd_status_packet_filter():
    return _create_response_filter(HCI_Event_Command_Status)


class HCIThread(RxThread):
    RESPONSE_TIMEOUT_SECS = 5.0

    def send_cmd(self, scapy_hci_cmd,
                 response_filter_creator=_create_hci_cmd_complete_packet_filter(),
                 response_timeout_secs=RESPONSE_TIMEOUT_SECS):
        response_queue = None
        if response_filter_creator:
            response_filter = response_filter_creator(scapy_hci_cmd)
            response_queue = Queue.Queue()
            self.add_packet_queue(response_filter, response_queue)

        full_hci_cmd = HCI_Hdr() / HCI_Command_Hdr() / scapy_hci_cmd
        self.socket.send(full_hci_cmd)

        if response_queue:
            try:
                cmd_status = response_queue.get(
                    block=True, timeout=response_timeout_secs)
            except Queue.Empty:
                raise HCIResponseTimeoutException(
                    "HCI command timed out: %s" %
                    full_hci_cmd.lastlayer().summary())
            return cmd_status

    def cmd_reset(self):
        self.send_cmd(HCI_Cmd_Reset())

    def cmd_set_event_filter_clear_all_filters(self):
        self.send_cmd(HCI_Cmd_Set_Event_Filter())

    def cmd_set_event_mask(self, mask=hci_event_mask.all_enabled_str()):
        self.send_cmd(HCI_Cmd_Set_Event_Mask(mask=mask))

    def cmd_le_host_supported(self, le_supported=True):
        self.send_cmd(HCI_Cmd_LE_Host_Supported(
            supported=1 if le_supported else 0,
            simultaneous=0))  # As per 4.2 spec: "This value shall be ignored."

    def cmd_le_read_buffer_size(self):
        self.send_cmd(HCI_Cmd_LE_Read_Buffer_Size())

    def cmd_read_bd_addr(self):
        def _create_read_bd_addr_response_filter(request_packet):
            def _read_bd_addr_response_filter(packet):
                return packet.getlayer(HCI_Cmd_Complete_Read_BD_Addr) \
                       is not None
            return _read_bd_addr_response_filter
        resp = self.send_cmd(
            HCI_Cmd_Read_BD_Addr(),
            response_filter_creator=_create_read_bd_addr_response_filter)
        return str(resp[HCI_Cmd_Complete_Read_BD_Addr])

    def cmd_le_scan_enable(self, enable, filter_dups=True):
        self.send_cmd(HCI_Cmd_LE_Set_Scan_Enable(
            enable=enable, filter_dups=filter_dups))

    def cmd_le_scan_params(self, active_scanning=True, interval_ms=10,
                           window_ms=10, **kwargs):
        scan_type = 1 if active_scanning else 0
        self.send_cmd(HCI_Cmd_LE_Set_Scan_Parameters(
            type=scan_type, interval=interval_ms * 0.625,
            window=window_ms * 0.625, **kwargs))

    def cmd_le_create_connection(self, address,
                                 is_identity_address=False,
                                 interval_ms=10,
                                 window_ms=10, **kwargs):
        address_type_map = {
            (True, False):  0x00,  # Public
            (False, False): 0x01,  # Random
            (True, True):   0x02,  # Public Identity
            (False, True):  0x03,  # Random Identity
        }
        self.send_cmd(HCI_Cmd_LE_Create_Connection(
            paddr=address.macstr(),
            patype=address_type_map[(address.is_public(), is_identity_address)],
            interval=interval_ms * 0.625,
            window=window_ms * 0.625,
            **kwargs),
            response_filter_creator=_create_hci_cmd_status_packet_filter())

    def cmd_le_connection_create_cancel(self):
        self.send_cmd(HCI_Cmd_LE_Create_Connection_Cancel())

    def cmd_disconnect(self, handle):
        self.send_cmd(
            HCI_Cmd_Disconnect(handle=handle),
            response_filter_creator=_create_hci_cmd_status_packet_filter())

    def cmd_le_update_conn_params(self, handle, params):
        self.send_cmd(HCI_Cmd_LE_Connection_Update(
                handle=handle,
                min_interval=params[0], max_interval=params[1],
                latency=params[2], timeout=params[3],
                min_ce=1, max_ce=0xffff),
            response_filter_creator=_create_hci_cmd_status_packet_filter())


class BTStack(object):
    def __init__(self, pyusb_dev=None):
        if not pyusb_dev:
            pyusb_dev = \
                pyusb_bt_sockets.find_first_bt_adapter_pyusb_device_or_raise()
        self.hci_socket = pyusb_bt_sockets.PyUSBBluetoothHCISocket(pyusb_dev)
        self.hci = HCIThread(self.hci_socket)
        self.cb_thread = CallbackThread()
        self.cb_thread.register_with_rx_thread(self.hci)
        self.is_scannning_enabled = False
        self.connection_mgr = ConnectionManager(
            self.hci, self.cb_thread)
        self.address = None

    def start(self):
        LOG.debug("BTStack start()")

        # During reset, just ignore and eat all packets that might come in:
        ignore_queue = Queue.Queue()
        self.hci.add_packet_queue(lambda packet: True, ignore_queue)
        self.hci.start()
        self.hci.cmd_reset()
        self.hci.remove_packet_queue(ignore_queue)

        self.cb_thread.start()

        self.hci.cmd_set_event_filter_clear_all_filters()
        self.hci.cmd_set_event_mask()
        self.hci.cmd_le_host_supported()

        # "The LE_Read_Buffer_Size command must be issued by the Host before it
        #  sends any data to an LE Controller":
        self.hci.cmd_le_read_buffer_size()

        self.address = self.hci.cmd_read_bd_addr()

    def start_scan(self):
        assert self.is_scannning_enabled is False
        self.hci.cmd_le_scan_params()
        self.hci.cmd_le_scan_enable(True)
        self.is_scannning_enabled = True

    def stop_scan(self):
        assert self.is_scannning_enabled is True
        self.hci.cmd_le_scan_enable(False)
        self.is_scannning_enabled = False

    def connect(self, address):
        return self.connection_mgr.connect(address)

    def disconnect(self, connection):
        self.connection_mgr.disconnect(connection)

    def update_conn_params(self, connection, params, callback):
        self.connection_mgr.update_conn_params(connection, params, callback)

    def quit(self):
        LOG.debug("BTStack quit()")
        self.hci.cmd_reset()
        self.hci.kill()
        self.cb_thread.kill()


def has_bt_adapter():
    return pyusb_bt_sockets.has_bt_adapter()
