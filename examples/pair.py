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
    connection = u.connect(Address("8F:29:FB:1C:55:5A"), timeout=5.0)
    # FIXME: add synchronous util call for pair()
    connection.sm.pair()
    # Stay connected for 15 seconds,
    time.sleep(6)
    # ... then disconnect:
    u.disconnect(connection)
except pybluetooth.exceptions.TimeoutException as e:
    LOG.debug("Timed out trying to connect...")

# Tear down the stack:
b.quit()
