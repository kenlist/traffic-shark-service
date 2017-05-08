from scapy.all import *
from scapy.contrib.coap import *

bind_layers(UDP, CoAP, sport=9493)
bind_layers(UDP, CoAP, dport=9493)
