#!/usr/bin/env python

import logging

from pybluetooth import BTStack
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

# Scan for a couple seconds, then print out the found reports:
reports = u.scan(2)
for report in reports:
    report.show()

# Tear down the stack:
b.quit()
