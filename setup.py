from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

import sys


class PyTest(TestCommand):
    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here because outside the eggs aren't loaded
        import pytest
        errno = pytest.main(["-v"])
        sys.exit(errno)

__version__ = None  # Overwritten by executing version.py.
with open('pybluetooth/version.py') as f:
    exec(f.read())

requires = [
    'scapy==2.3.2.dev0',
    # scapy dependencies that aren't installed by scapy's setup.py itself:
    'dnet==1.12',
    'pcapy==0.10.10',
    'pyusb==1.0.0b2',
    'six==1.10.0',
    'pbr==1.9.1',
]

setup(name='pybluetooth',
      version=__version__,
      description='Python Bluetooth Library',
      long_description=open('README.md').read(),
      url='https://github.com/pebble/pybluetooth',
      author='Pebble Technology Corporation',
      author_email='martijn@pebble.com',
      license='MIT',
      packages=find_packages(),
      install_requires=requires,
      tests_require=[
        'pytest',
        'pytest-mock',
        'scapy',
        'dnet',
        'pcapy',
      ],
      cmdclass={'test': PyTest},
      classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Topic :: System :: Hardware :: Hardware Drivers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Software Development :: Embedded Systems',
        'Topic :: System :: Networking',
      ],
      zip_safe=True)
