#!/usr/bin/env python
""" Class that exposes a synchronous API for various Bluetooth activities.
"""

import logging
import Queue
import time

from scapy.layers.bluetooth import *


LOG = logging.getLogger("pybluetooth")


class BTStackSynchronousUtils(object):
    def __init__(self, btstack):
        self.b = btstack

    def scan(self, duration_secs=5.0):
        LOG.debug("BTStackSynchronousUtils scan()")
        adv_report_queue = Queue.Queue()

        def adv_packet_filter(packet):
            return packet.getlayer(HCI_LE_Meta_Advertising_Report) != None
        self.b.hci.add_packet_queue(adv_packet_filter, adv_report_queue)
        self.b.hci.cmd_le_scan_params()
        self.b.hci.cmd_le_scan_enable(True)
        time.sleep(duration_secs)
        self.b.hci.cmd_le_scan_enable(False)
        self.b.hci.remove_packet_queue(adv_report_queue)

        reports = []
        while True:
            try:
                r = adv_report_queue.get_nowait()
                reports += [r[HCI_LE_Meta_Advertising_Report]]
            except:
                break
        return reports


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

    # Scan for a couple seconds, then print out the found reports:
    u = BTStackSynchronousUtils(b)
    reports = u.scan(5)
    for report in reports:
        report.show()
