#!/usr/bin/env python3

from scapy.all import *

a = IP()
a.dst = "8.8.8.8"

class flag():
    a = 0

def print_pkt(pkt):
    if pkt[IP].src == "8.8.8.8":
        pkt.show()
        flag.a = 1

for i in range(1,150):
    a.ttl = i
    b = ICMP()
    p = a/b
    send(p)
    pkt = sniff(filter="icmp",timeout = 0.5, prn=print_pkt)
    if flag.a == 1:
        print("The required TTL is " ,str(i))
        break
