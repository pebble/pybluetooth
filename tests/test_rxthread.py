import unittest

try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock

from Queue import Queue, Empty
from scapy.layers.bluetooth import *
from scapy.packet import Packet
from threading import Semaphore


from pybluetooth import RxThread


class TestRxThread(unittest.TestCase):
    def setUp(self):
        self.socket = MagicMock()
        self.rx_thread = RxThread(self.socket)

        self.mock_recv_queue = Queue()

        def mock_recv(x=512, timeout_secs=10.0):
            packet = self.mock_recv_queue.get()
            return packet
        self.socket.recv = mock_recv

        self.rx_thread.start()

    def simulate_recv_packet(self, packet):
        self.mock_recv_queue.put(packet)

    def test_add_remove_queue(self):
        # Add the queue and receive a packet:
        queue = Queue()
        self.rx_thread.add_packet_queue(lambda packet: True, queue)
        self.simulate_recv_packet(Packet())
        packet = queue.get(block=True, timeout=0.1)
        self.assertEquals(packet, Packet())

        # Remove the queue, receive a packet, it shouldn't get added:
        self.rx_thread.remove_packet_queue(queue)
        self.simulate_recv_packet(Packet())
        with self.assertRaises(Empty):
            packet = queue.get(block=False, timeout=0.1)

    def test_queues_filtered_by_packet(self):
        queue = Queue()

        def adv_packet_filter(packet):
            return packet.getlayer(HCI_LE_Meta_Advertising_Report) != None
        self.rx_thread.add_packet_queue(adv_packet_filter, queue)

        # Receive cmd status, expect NOT to be added to queue:
        cmd_status_evt_packet = (
            HCI_Hdr() / HCI_Event_Hdr() / HCI_Event_Command_Status())
        self.simulate_recv_packet(cmd_status_evt_packet)
        with self.assertRaises(Empty):
            packet = queue.get(block=False, timeout=0.1)

        # Receive ad report packet, expect to be added to queue:
        adv_evt_packet = (
            HCI_Hdr() / HCI_Event_Hdr() / HCI_Event_LE_Meta() /
            HCI_LE_Meta_Advertising_Report())
        self.simulate_recv_packet(adv_evt_packet)
        recv_packet = queue.get(block=True, timeout=0.1)
        self.assertEquals(recv_packet, adv_evt_packet)


if __name__ == '__main__':
    unittest.main()
