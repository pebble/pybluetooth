""" Class that exposes a synchronous API for various Bluetooth activities.
"""

import logging
import Queue
import time

from scapy.layers.bluetooth import *

from pybluetooth.address import *
from pybluetooth.exceptions import *


LOG = logging.getLogger("pybluetooth")


class BTStackSynchronousUtils(object):
    def __init__(self, btstack):
        self.b = btstack

    def scan(self, duration_secs=5.0):
        LOG.debug("BTStackSynchronousUtils scan()")
        adv_report_queue = Queue.Queue()

        def adv_packet_filter(packet):
            return packet.getlayer(HCI_LE_Meta_Advertising_Report) is not None
        self.b.hci.add_packet_queue(adv_packet_filter, adv_report_queue)
        self.b.start_scan()
        time.sleep(duration_secs)
        self.b.stop_scan()
        self.b.hci.remove_packet_queue(adv_report_queue)

        reports = []
        while True:
            try:
                r = adv_report_queue.get_nowait()
                reports += [r[HCI_LE_Meta_Advertising_Report]]
            except:
                break
        return reports

    def scan_until_match(self, packet_filter, timeout=None):
        LOG.debug("BTStackSynchronousUtils scan_until_match()")
        adv_report_queue = Queue.Queue()

        def adv_packet_filter(packet):
            if packet.getlayer(HCI_LE_Meta_Advertising_Report) is None:
                return False
            return packet_filter(packet[HCI_LE_Meta_Advertising_Report])

        self.b.hci.add_packet_queue(adv_packet_filter, adv_report_queue)
        self.b.start_scan()
        try:
            report = adv_report_queue.get(block=True, timeout=timeout)
        except Queue.Empty:
            raise TimeoutException()
        finally:
            self.b.stop_scan()
            self.b.hci.remove_packet_queue(adv_report_queue)
        return report

    def connect(self, adv_filter_or_address, timeout=None,
                should_cancel_connecting_on_timeout=True):
        LOG.debug("BTStackSynchronousUtils connect()")
        if isinstance(adv_filter_or_address, Address):
            address = adv_filter_or_address
        else:
            adv_report = self.scan_until_match(
                adv_filter_or_address, timeout=timeout)
            address = Address.from_packet(adv_report)
        connection = self.b.connect(address)
        try:
            connection.wait_until_connected(timeout=timeout)
        except TimeoutException as e:
            if should_cancel_connecting_on_timeout:
                self.disconnect(connection)
            raise e
        return connection

    def disconnect(self, connection, timeout=None):
        self.b.disconnect(connection)
        connection.wait_until_disconnected(timeout=timeout)

    def update_conn_params(self, connection, params, timeout=None):
        q = Queue.Queue()

        def callback(actual_params):
            q.put(actual_params)
        self.b.update_conn_params(connection, params, callback)
        return q.get(True, timeout)
