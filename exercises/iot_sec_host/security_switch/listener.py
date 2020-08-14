import sys

from scapy.all import sniff, get_if_list
from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.layers.inet import Ether, IP, UDP, TCP
from exercises.iot_sec_host.security_switch.cache_loader import *

IFACE = 'eth0'
CACHE_DNS = load_cache_dns()
CACHE_MUD = load_cache_mud()

if __name__ == '__main__':
    pkt = Ether(src="ff:ff:ff:ff:ff:ff", dst="ff:ff:ff:ff:ff:ff") / IP(dst='10.0.5.5', tos=4) / TCP() / 'test'
    print(pkt.tos)
    print('Sniffing on %s' % IFACE)
    sys.stdout.flush()
    sniff(iface=IFACE, prn=lambda x: handle_pkt(x))


def handle_pkt(pkt):
    print('got a packet')
    pkt.show2()
    dscp_value = tos_to_dscp_value(pkt.tos)
    if dscp_value == 0:
        action_noniot(pkt)
    else:
        action_iot(pkt, dscp_value)
    sys.stdout.flush()


def action_iot(pkt, dscp_value):
    pass


def action_noniot(pkt):
    pass


def tos_to_dscp_value(tos):
    return int(('{0:08b}'.format(tos))[:6], 2)


def get_if():
    ifs = get_if_list()
    captured_iface = None
    for i in get_if_list():
        if IFACE in i:
            captured_iface = i
            break
    if not captured_iface:
        print('Cannot find eth0 interface')
        exit(1)
    return captured_iface
