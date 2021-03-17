#!/usr/bin/env python3

from scapy.all import *

def print_pkt(pkt):
pkt.show()

pkt = sniff(iface=’br-c93733e9f913’, filter=’icmp’, prn=print_pkt)