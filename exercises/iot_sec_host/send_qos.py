#!/usr/bin/env python

import argparse
import socket

from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP, TCP

from time import sleep


def get_if():
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--p", help="Protocol name To send TCP/UDP etc packets", type=str)
    parser.add_argument("--des", help="IP address of the destination", type=str)
    parser.add_argument("--m", help="Raw Message", type=str)
    parser.add_argument("--dur", help="in seconds", type=str)
    parser.add_argument("--tos", help="in seconds", type=int)
    args = parser.parse_args()

    if args.p and args.des and args.m and args.dur:
        addr = socket.gethostbyname(args.des)
        iface = get_if()
        if args.p == 'UDP':
            pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=addr, tos=args.tos) / UDP(dport=4321, sport=1234) / args.m
            pkt.show2()
            try:
                for i in range(int(args.dur)):
                    sendp(pkt, iface=iface)
                    sleep(1)
            except KeyboardInterrupt:
                raise
        elif args.p == 'TCP':
            pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=addr, tos=args.tos / TCP() / args.m
            pkt.show2()
            try:
                for i in range(int(args.dur)):
                    sendp(pkt, iface=iface)
                    sleep(1)
            except KeyboardInterrupt:
                raise


if __name__ == '__main__':
    main()