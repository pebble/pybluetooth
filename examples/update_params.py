#!/usr/bin/env python

import logging
import pybluetooth
import time

from pybluetooth import BTStack
from pybluetooth.address import *
from pybluetooth.synchronous import BTStackSynchronousUtils

from random import randint

LOG = logging.getLogger("pybluetooth")

LOG.setLevel(logging.DEBUG)
lsh = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s> %(message)s')
lsh.setFormatter(formatter)
LOG.addHandler(lsh)

b = BTStack()
b.start()

u = BTStackSynchronousUtils(b)


def adv_report_filter(adv_report):
    # return True  # Just connect to anything that advertises...
    return adv_report.addr == "75:a7:a8:46:38:32"

# Infinitely try to connect...
while True:
    connection = u.connect(adv_report_filter, timeout=10.0)
    LOG.debug("Connection %s" % connection)

    # Infinitely change up the connection parameters to a random set...
    i = 0
    while True:
        i = (i + 1) % 2
        try:
            # min_intv = randint(6, 7)
            # max_intv = min_intv  # + 10
            # req_params = (min_intv, max_intv, 0, 60)
            param_sets = [
                (135, 160, 0, 60),
                (6, 6, 0, 60),
            ]
            req_params = param_sets[i]
            actual_params = u.update_conn_params(connection, req_params)
            print("Updated to: %s" % str(actual_params))
        except Exception as e:
            print(e)
            break
    time.sleep(0.1)
    u.disconnect(connection)


# Tear down the stack:
b.quit()
