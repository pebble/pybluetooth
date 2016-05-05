#!/usr/bin/env python

import logging
import pybluetooth
import time

from pybluetooth import BTStack
from pybluetooth.address import *
from pybluetooth.synchronous import BTStackSynchronousUtils


LOG = logging.getLogger("pybluetooth")

LOG.setLevel(logging.DEBUG)
lsh = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s> %(message)s')
lsh.setFormatter(formatter)
LOG.addHandler(lsh)

b = BTStack()
b.start()

u = BTStackSynchronousUtils(b)

# Attempt to connect to a device by address:
try:
    connection = u.connect(Address("c9:ea:a5:b8:c8:10"), timeout=5.0)
    # Stay connected for 15 seconds,
    time.sleep(15)
    # ... then disconnect:
    u.disconnect(connection)
except pybluetooth.exceptions.TimeoutException as e:
    LOG.debug("Timed out trying to connect...")


# Connect and disconnect 100x in quick succession. Connect by scanning
# and matching advertisement packets:
def adv_report_filter(adv_report):
    return True  # Just connect to anything that advertises...
    # return adv_report.addr == "c9:ea:a5:b8:c8:10"

for _ in xrange(0, 100):
    connection = u.connect(adv_report_filter, timeout=10.0)
    LOG.debug("Connection %s" % connection)
    u.disconnect(connection)

# Tear down the stack:
b.quit()
