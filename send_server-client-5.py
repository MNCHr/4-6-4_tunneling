#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, IPv6
from scapy.all import hexdump, BitField, BitFieldLenField, ShortEnumField, X3BytesField, ByteField, XByteField

def main():
    sel = int(sys.argv[1])
    iface = "veth0"
    global pkt1, pkt2, pkt3_1, pkt3_2, pkt4, pkt6

# server -> client
    pkt1 = Ether(src=get_if_hwaddr(iface), dst='00:00:00:00:00:01') / IP(src='10.10.1.12', dst='10.10.100.5') / "server->client test"
# client -> server
    pkt2 = Ether(src=get_if_hwaddr(iface), dst='00:00:00:00:00:02') / IP(src='10.10.100.5', dst='10.10.1.12') / "client->server test"
# client -> server
    pkt3 = Ether(src=get_if_hwaddr(iface), dst='00:00:00:00:00:03') / IPv6(nh=0) / IP(src='10.10.100.5', dst='10.10.1.12') / "client->server, v6 test"

# client -> server
    pkt4 = Ether(src=get_if_hwaddr(iface), dst='00:00:00:00:00:04') / IP(src='10.10.100.5', dst='10.10.1.12') / UDP(dport=12000) / "client->server, UDP test"
# server -> client
    pkt5 = Ether(src=get_if_hwaddr(iface), dst='00:00:00:00:00:04') / IP(src='10.10.1.12', dst='10.10.100.5') / UDP(dport=10005) / "server->client, UDP test"

# client -> server, encapsulated
    pkt6 = Ether(src=get_if_hwaddr(iface), dst='00:00:00:00:00:05') / IPv6(nh=0) / IP(src='10.10.100.5', dst='10.10.1.12') / UDP(dport=12000) / "client->server, decap test"

#    out_ether = Ether(src=get_if_hwaddr(iface), dst='00:00:00:00:00:01', type=0x894f)
#    in_ether =  Ether(src=get_if_hwaddr(iface), dst='00:00:00:00:00:01', type=0x800)
#    pkt1 = desc_hdr(vdp_id=10) / in_ether / IP(src=addr,dst=addr1) / "hi"
    if sel==1:
        pkt1.show()
        hexdump(pkt1)
        sendp(pkt1, iface=iface, verbose=False)
#        print "sending arp packet"
#        print "==========================="
    elif sel==2:
        pkt2.show()
        hexdump(pkt2)
        sendp(pkt2, iface=iface, verbose=False)

    elif sel==3:
        pkt3.show()
        hexdump(pkt3)
        sendp(pkt3, iface=iface, verbose=False)
    
    elif sel==4:
        pkt4.show()
        hexdump(pkt4)
        sendp(pkt4, iface=iface, verbose=False)

    elif sel==5:
        pkt5.show()
        hexdump(pkt5)
        sendp(pkt5, iface=iface, verbose=False)

    elif sel==6:
        pkt6.show()
        hexdump(pkt6)
        sendp(pkt6, iface=iface, verbose=False)





if __name__ == '__main__':
    main()
