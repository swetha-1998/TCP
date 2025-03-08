#!/bin/env python3

import sys
from scapy.all import *

print("SENDING ICMP PACKET.........")
a = IP()
a.dst = '8.8.8.8'
a.ttl = int(sys.argv[1]) 
b = ICMP()
h = sr1(a/b)
print("Router: {}".format(h.src))
