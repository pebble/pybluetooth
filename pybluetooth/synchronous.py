#!/usr/bin/env python
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


if __name__ == '__main__':
    from pybluetooth import BTStack, has_bt_adapter

    LOG.setLevel(logging.DEBUG)
    lsh = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s> %(message)s')
    lsh.setFormatter(formatter)
    LOG.addHandler(lsh)

    b = BTStack()
    b.start()

    u = BTStackSynchronousUtils(b)

    # Scan for a couple seconds, then print out the found reports:
    reports = u.scan(2)
    for report in reports:
        report.show()

    # Connect and disconnect 100x in quick succession:
    def adv_report_filter(adv_report):
        return True  # Just connect to anything
        # return adv_report.addr == "c9:ea:a5:b8:c8:10"

    for _ in xrange(0, 100):
        connection = u.connect(adv_report_filter, timeout=10.0)
        # connection = u.connect(Address("c9:ea:a5:b8:c8:10"), timeout=10.0)
        LOG.debug("Connection %s" % connection)
        u.disconnect(connection)

    # Tear down the stack:
    b.quit()

    # Wait a bit so we can see in the log what happens after quitting:
    import time
    time.sleep(1)
