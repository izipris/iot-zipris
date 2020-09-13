#!/usr/bin/env python

import sys

from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP

# Constants
ARGS_COUNT = 2
ARGS_HOST_IDX = 1
EXIT_CODE_ERROR = 1
ERROR_USAGE = 'Usage: python receive_qos.py <host name>'


def tos_to_dscp_value(tos):
    return int(('{0:08b}'.format(tos))[:6], 2)


def get_if():
    iface = None
    for i in get_if_list():
        if host_name + '-eth0' in i:
            iface = i
            break
    if not iface:
        print('Cannot find eth0 interface')
        exit(EXIT_CODE_ERROR)
    return iface


def handle_pkt(pkt):
    if IP in pkt:
        connection = (pkt[IP].src, pkt[IP].dst, tos_to_dscp_value(pkt[IP].tos))
        print('got a packet: ' + str(connection))
        sys.stdout.flush()


def parse_arguments():
    global host_name
    if len(sys.argv) != ARGS_COUNT:
        print(ERROR_USAGE)
        quit(EXIT_CODE_ERROR)
    host_name = sys.argv[ARGS_HOST_IDX]


def main():
    parse_arguments()
    iface = host_name + '-eth0'
    print('sniffing on %s' % iface)
    sys.stdout.flush()
    sniff(iface=iface, prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()
