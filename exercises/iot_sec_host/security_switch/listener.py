#!/usr/bin/env python
import sys

from scapy.all import sendp, get_if_list
from scapy.all import sniff
from scapy.layers.inet import IP
import json

CACHE_FILE_DNS = './security_switch/cache/dns_cache.json'
CACHE_FILE_MUD = './security_switch/cache/mud_cache.json'


def load_json_file(file_path):
    with open(file_path) as file:
        data = json.load(file)
    return data


IFACE = 'eth0'
CACHE_DNS = load_json_file(CACHE_FILE_DNS)
CACHE_MUD = load_json_file(CACHE_FILE_MUD)


def action_iot(pkt, dscp_value):
    mud_file = get_mud_from_cache(dscp_value)
    if mud_file is not None:
        acl_list = mud_file['ietf-access-control-list:acls']['acl']
        for acl in acl_list:
            for ace in acl['aces']['ace']:
                if 'ietf-acldns:dst-dnsname' in ace['matches']['ipv4']:
                    allowed_domain = ace['matches']['ipv4']['ietf-acldns:dst-dnsname']
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
    print('Sniffing on %s' % IFACE)
    sys.stdout.flush()
    sniff(iface=IFACE, prn=lambda x: handle_pkt(x))
