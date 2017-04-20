#!/usr/bin/python

import sys

sys.path.insert(1, "packages")

from tsd.scripts import runner
runner.run()

# from scapy.all import *

# def _capture_pkt_callback(pkt):
#     pkt.show()

# sniff(iface="wlan0", filter="host 172.24.1.92", count=1)