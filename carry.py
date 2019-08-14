#!/usr/bin/env python
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, IPv6
from scapy.layers.inet import _IPOption_HDR

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "veth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def carry_pkt(pkt):
    print "carry a packet "
    pkt.show2()
    sys.stdout.flush()
    sendp(pkt, iface='veth6', verbose=False)

def main():
    iface = 'veth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="ip host 10.10.1.12", iface = iface, 
          prn = lambda x: carry_pkt(x))

if __name__ == '__main__':
    main()
