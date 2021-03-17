#!/usr/bin/env python3

from scapy.all import *

a = IP()
a.dst = "10.0.2.3"
a.src = "8.8.8.8"
b = ICMP()
p = a/b
send(p)
ls(a)
