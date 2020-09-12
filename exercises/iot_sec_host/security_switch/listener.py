#!/usr/bin/env python
import json
import sys

from scapy.all import get_if_list
from scapy.all import sniff
from scapy.layers.inet import IP

from exercises.iot_sec_host.security_switch.model.Connection import Connection

CACHE_FILE_DNS = './security_switch/cache/dns_cache.json'
CACHE_FILE_MUD = './security_switch/cache/mud_cache.json'
CACHE_FILE_CLIENTS = './security_switch/cache/clients_cache.json'


def load_json_file(file_path):
    with open(file_path) as file:
        data = json.load(file)
    return data


IFACE = 'eth0'
DSCP_NON_IOT = 0
ARGS_COUNT = 2
ARGS_HOST_IDX = 1
EXIT_CODE_ERROR = 1
ERROR_USAGE = 'Usage: python listener.py <host name>'

CACHE_DNS = load_json_file(CACHE_FILE_DNS)
CACHE_MUD = load_json_file(CACHE_FILE_MUD)
CACHE_CLIENTS = load_json_file(CACHE_FILE_CLIENTS)
CACHE_CONNECTION = []


def parse_arguments():
    global host_name
    if len(sys.argv) != ARGS_COUNT:
        print(ERROR_USAGE)
        quit(EXIT_CODE_ERROR)
    host_name = sys.argv[ARGS_HOST_IDX]


def is_iot_client(connection):
    if connection.get_dscp_value() == DSCP_NON_IOT:
        return False
    for entity in CACHE_CLIENTS['entities']:
        if entity['ip'] == connection.get_ip_src() and entity['dscp_value'] == connection.get_dscp_value:
            return True
    return False


def action_iot(connection):
    connection_verified = False
    mud_file = get_mud_from_cache(connection.get_ip_src(), connection.get_dscp_value())
    if mud_file is not None:
        acl_list = mud_file['ietf-access-control-list:acls']['acl']
        for acl in acl_list:
            for ace in acl['aces']['ace']:
                if 'ietf-acldns:dst-dnsname' in ace['matches']['ipv4']:
                    allowed_domain = ace['matches']['ipv4']['ietf-acldns:dst-dnsname']
                    ip_addr = get_ip_by_domain(allowed_domain)
                    if connection.get_ip_dst() == ip_addr:
                        connection_verified = True
                        break
            if connection_verified:
                break
        if not connection_verified:
            action_block_connection(connection)
    add_to_connections_cache(connection)


def add_to_connections_cache(connection):
    CACHE_CONNECTION.append(connection.get_tuple())


def action_block_connection(connection):
    print('SHOULD BE BLOCKED')


def get_mud_from_cache(ip, dscp_value):
    for entity in CACHE_MUD['entities']:
        if entity['ip'] == ip and entity['dscp_value'] == dscp_value:
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
    captured_iface = None
    for i in get_if_list():
        if host_name + '-' + IFACE in i:
            captured_iface = i
            break
    if not captured_iface:
        print('Cannot find eth0 interface')
        exit(1)
    return captured_iface


def handle_pkt(pkt):
    print('got a packet')
    pkt.show2()
    connection = Connection(pkt[IP].src, pkt[IP].dst, pkt[IP].tos)
    if is_iot_client(connection) and connection.get_tuple() not in CACHE_CONNECTION:
        action_iot(connection)
    sys.stdout.flush()


if __name__ == '__main__':
    print('Sniffing on %s' % host_name + '-' + IFACE)
    sys.stdout.flush()
    sniff(iface=host_name + '-' + IFACE, prn=lambda x: handle_pkt(x))
