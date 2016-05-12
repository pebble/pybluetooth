# Python Bluetooth Stack

- The goal of this library is to be a pure-Python implementation of a Bluetooth LE host stack,
  geared towards, but not limited to, automated testing of Bluetooth devices such as [Pebble][0]
  smartwatches.
- Focussed on Bluetooth Low Energy (4.x) for now.
- Uses [PyUSB][1] to communicate with standard Bluetooth USB dongles.
- Tested on Mac OS X:
    - [CSR8510 BT 4.0 USB dongle][2], should work with other standard BT 4.0 USB dongles.
    - Built-in Bluetooth of my Mid-2015 MacBook Pro 15".
- Relies on [scapy][3] to do most of the packet parsing / building.
- Inspired by [mikeryan's PyBT][5] project.
- *WARNING: Many things aren't implemented! Please contribute!*

### Installation (OS X)

Step 1: Install [scapy][3] system dependencies:

```
$ brew install libpcap libdnet
```

Step 2: Because this project currently depends on a features in [scapy][3] that have not yet been
released, you'll need install scapy from Pebble's clone. If you're a Pebble employee, you should be
able to install [scapy][3] from the internal pypi server, and therefore skip this step.

```
$ git clone https://github.com/pebble/scapy.git
$ cd scapy && pip install -e .
```

Step 3: Then go on to install `pybluetooth`:

```
$ git clone https://github.com/pebble/pybluetooth.git
$ cd pybluetooth && pip install -e .
```

Step 4: Try out one of the examples:

```
$ ./examples/scan.py
```

### Using a Bluetooth USB dongle on Mac OS X

OS X ships with drivers for various Bluetooth devices, so chances are that the built-in drivers
(kernel extensions or .kexts) will latch onto the dongle as soon as you plug it in. To prevent this
you can unload or rename the .kext (see `/System/Library/Extensions/`) but this will also break your
Mac's built-in Bluetooth. If you want to use the built-in Bluetooth of your Mac, there is no other
option than to disable the Bluetooth .kexts. The steps to do this are:

1. Disable [OS X' System Integrity Protection][4] by following one of the numerous how-tos on the interwebs.
2. `$ sudo mv /System/Library/Extensions/IOBluetoothFamily.kext /System/Library/Extensions/IOBluetoothFamily.kext.dontload`
3. Reboot.
4. Done ;)

Alternatively, some chipsets support changing the USB VendorId and ProductId of the dongle. If the
VendorId and/or ProductId of the dongle doesn't match with what the driver can support, it will
leave the dongle along and free for this library to use it.

Dongles that allow the USB info to be changed:

- CSR based dongles: use PSTool, which is part of CSR's' BlueSuite developer tools.
- ...

[0]: http://www.pebble.com/
[1]: http://walac.github.io/pyusb/
[2]: http://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3Daps&field-keywords=CSR8510
[3]: https://github.com/pebble/scapy
[4]: https://support.apple.com/en-us/HT204899
[5]: https://github.com/mikeryan/PyBT