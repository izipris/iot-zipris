import sys

from scapy.all import sniff, get_if_list
from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.layers.inet import Ether, IP, UDP, TCP
from exercises.iot_sec_host.security_switch.cache_loader import *

IFACE = 'eth0'
CACHE_DNS = load_cache_dns()
CACHE_MUD = load_cache_mud()


def action_iot(pkt, dscp_value):
    mud_file = get_mud_from_cache(dscp_value)
    if mud_file is not None:
        acl_list = mud_file['ietf-access-control-list:acls']['acl']
        for acl in acl_list:
            for ace in acl['aces']['ace']:
                allowed_domain = ace['matches']['ipv4']['ietf-acldns:src-dnsname']
                ip_addr = get_ip_by_domain(allowed_domain)
                if pkt[IP].dst == ip_addr:
                    action_iot_passed(pkt)
        action_iot_failed(pkt)


def action_noniot(pkt):
    pass


def action_iot_passed(pkt):
    pkt[IP].tos = 0
    try:
        sendp(pkt, iface=get_if())
    except KeyboardInterrupt:
        raise


def action_iot_failed(pkt):
    pass


def get_mud_from_cache(dscp_value):
    for entity in CACHE_MUD['entities']:
        if entity['dscp_value'] == dscp_value:
            return load_json_file(entity['mud_file'])
    return None  # TODO: DSCP value is unknown, unidentified device


def get_ip_by_domain(domain):
    for entity in CACHE_DNS['entities']:
        if entity['domain'] == domain:
            return entity['ip']
    return None  # TODO: cache miss, call DNS


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


def handle_pkt(pkt):
    print('got a packet')
    pkt.show2()
    dscp_value = tos_to_dscp_value(pkt[IP].tos)
    if dscp_value == 0:
        action_noniot(pkt)
    else:
        action_iot(pkt, dscp_value)
    sys.stdout.flush()


if __name__ == '__main__':
    pkt = Ether(src="ff:ff:ff:ff:ff:ff", dst="ff:ff:ff:ff:ff:ff") / IP(dst='10.0.5.5', tos=4) / TCP() / 'test'
    handle_pkt(pkt)
    print('Sniffing on %s' % IFACE)
    sys.stdout.flush()
    sniff(iface=IFACE, prn=lambda x: handle_pkt(x))
