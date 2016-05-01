import binascii
import logging
import Queue
from scapy.layers.bluetooth import *
from threading import Event, RLock, Thread

import hci_event_mask
import pyusb_bt_sockets

LOG = logging.getLogger("pybluetooth")


class HCIResponseTimeoutException(Exception):
    pass


class RxThread(Thread):
    def __init__(self, socket):
        super(RxThread, self).__init__()
        self.daemon = True
        self.is_killed = Event()
        self.socket = socket
        self.lock = RLock()
        self.packet_queues = dict()

    def synchronized(self, func):
        with self.lock:
            return func

    def run(self):
        while not self.is_killed.is_set():
            packet = self.socket.recv(timeout_secs=0.1)
            if packet is None:
                continue  # Timeout hit, loop again
            matching_queues = self.queues_filtered_by_packet(packet)
            if not matching_queues:
                LOG.warn(
                    "Dropping packet, no handler queue!\n%s" % packet.show())
            for queue in matching_queues:
                queue.put(packet)

    def kill(self):
        self.is_killed.set()

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


class HCIThread(RxThread):
    RESPONSE_TIMEOUT_SECS = 5.0

    def _create_hci_cmd_status_packet_filter(request_packet):
        opcode = request_packet.overload_fields[HCI_Command_Hdr]['opcode']

        def _hci_cmd_status_packet_filter(packet):
            if not packet.getlayer(HCI_Event_Command_Complete):
                return False
            return packet.opcode == opcode
        return _hci_cmd_status_packet_filter

    def send_cmd(self, scapy_hci_cmd,
                 response_filter_creator=_create_hci_cmd_status_packet_filter,
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
                return packet.getlayer(HCI_Cmd_Complete_Read_BD_Addr) != None
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


class BTStack(object):
    def __init__(self, pyusb_dev=None):
        if not pyusb_dev:
            pyusb_dev = \
                pyusb_bt_sockets.find_first_bt_adapter_pyusb_device_or_raise()
        self.hci_socket = pyusb_bt_sockets.PyUSBBluetoothHCISocket(pyusb_dev)
        self.hci = HCIThread(self.hci_socket)

    def start(self):
        LOG.debug("BTStack start()")

        # During reset, just ignore and eat all packets that might come in:
        ignore_queue = Queue.Queue()
        self.hci.add_packet_queue(lambda packet: True, ignore_queue)
        self.hci.start()
        self.hci.cmd_reset()
        self.hci.remove_packet_queue(ignore_queue)

        self.hci.cmd_set_event_filter_clear_all_filters()
        self.hci.cmd_set_event_mask()
        self.hci.cmd_le_host_supported()

        # "The LE_Read_Buffer_Size command must be issued by the Host before it
        #  sends any data to an LE Controller":
        self.hci.cmd_le_read_buffer_size()

        self.addr = self.hci.cmd_read_bd_addr()

    def quit(self):
        LOG.debug("BTStack quit()")
        self.hci.cmd_reset()
        self.hci.kill()


def has_bt_adapter():
    return pyusb_bt_sockets.has_bt_adapter()
