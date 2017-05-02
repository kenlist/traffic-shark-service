#!/usr/bin/python

import sys

sys.path.insert(1, "packages")

from tsd.scripts import runner
runner.run()

# from scapy.all import *

# def _capture_pkt_callback(pkt):
#     print pkt.time

# sniff(iface="wlan0", filter="host 172.24.1.132", prn=_capture_pkt_callback, count=3)

# from scapy.all import *
# pkts = sniff(iface="wlan0", filter="host 172.24.1.117", count=1)

# import json
# from collections import defaultdict

# def pkg_to_json(pkg):
#     results = defaultdict(dict)

#     try:
#         for index in range(50):

#             layer = pkg[index]

#             # Get layer name
#             layer_tmp_name = str(layer.aliastypes[0])
#             layer_start_pos = layer_tmp_name.rfind(".") + 1
#             layer_name = layer_tmp_name[layer_start_pos:-2].lower()

#             # Get the layer info
#             tmp_t = {}
#             for x, y in layer.default_fields.items():
#                 if y and not isinstance(y, (str, int, long, float, list, dict)):
#                     tmp_t[x].update(pkg_to_json(y))
#                 else:
#                     tmp_t[x] = y
#             results[layer_name] = tmp_t

#             try:
#                 tmp_t = {}
#                 for x, y in layer.fields.items():
#                     if y and not isinstance(y, (str, int, long, float, list, dict)):
#                         tmp_t[x].update(pkg_to_json(y))
#                     else:
#                         tmp_t[x] = y
#                 results[layer_name] = tmp_t
#             except KeyError:
#               # No custom fields
#                 pass
#     except IndexError:
#         # Package finish -> do nothing
#         pass

#     return json.dumps(results)


# from scapy.all import IP, TCP, DNS, DNSQR, UDP

# # print(pkg_to_json(IP(dst="8.8.8.8")/TCP(dport=80)/"hello World"))
# print(pkg_to_json(IP(dst="8.8.8.8")/UDP(dport=53)/DNS()/DNSQR(qname="terra.es")))