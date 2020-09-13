#!/usr/bin/env python
import json
import sys

import requests
from scapy.all import get_if_list
from scapy.all import sniff
from scapy.layers.inet import IP


class Connection:
    def __init__(self, ip_src, ip_dst, dscp_value):
        self.__ip_src = ip_src
        self.__ip_dst = ip_dst
        self.__dscp_value = dscp_value

    def get_ip_src(self):
        return self.__ip_src

    def get_ip_dst(self):
        return self.__ip_dst

    def get_dscp_value(self):
        return self.__dscp_value

    def get_tuple(self):
        return self.__ip_src, self.__ip_dst, self.__dscp_value


class WebDriver:
    @staticmethod
    def do_post(base_url, path, headers, body):
        url = base_url + path
        return requests.post(url, data=body, headers=headers, verify=False)


class SdnControllerWebDriver:
    def __init__(self, base_url, auth_token):
        self.__base_url = base_url
        self.__auth_token = auth_token

    def block_connection(self, connection):
        ROUTER_ADDR = '00:00:00:00:00:00:00:01'
        path = '/sdn/v2.0/of/datapaths/' + ROUTER_ADDR + '/flows'
        headers = {'Content-Type': 'application/json', 'X-AUTH-TOKEN': self.__auth_token}
        body = '''
        {
            "flow":{
                "priority": 60002,
                "match": [
                    {
                        "eth_type": "ipv4"
                    },
                    {
                        "ipv4_src": "%s"
                    },
                    {
                        "ipv4_dst": "%s"
                    }
                ],
                "instructions": [
                    {
                        "apply_actions": [
                            {
                                "set_mpls_ttl": 0
                            }
                        ]
                    }
                    
                ]
            }
        }
        ''' % (connection.get_ip_src(), connection.get_ip_dst())
        return WebDriver.do_post(self.__base_url, path, headers, body)


CACHE_FILE_DNS = './security_switch/cache/dns_cache.json'
CACHE_FILE_MUD = './security_switch/cache/mud_cache.json'
CACHE_FILE_CLIENTS = './security_switch/cache/clients_cache.json'


def load_json_file(file_path):
    with open(file_path) as file:
        data = json.load(file)
    return data


IFACE = 'eth0'
DSCP_NON_IOT = 0
ARGS_COUNT = 4
ARGS_HOST_IDX = 1
ARGS_CTRL_IDX = 2
ARGS_TOKEN_IDX = 3
EXIT_CODE_ERROR = 1
ERROR_USAGE = 'Usage: python listener.py <host name> <Controller base URL> <Controller auth token>'

CACHE_DNS = load_json_file(CACHE_FILE_DNS)
CACHE_MUD = load_json_file(CACHE_FILE_MUD)
CACHE_CLIENTS = load_json_file(CACHE_FILE_CLIENTS)
CACHE_CONNECTION = []


def parse_arguments():
    global host_name, controller_base_url, controller_auth_token
    if len(sys.argv) != ARGS_COUNT:
        print(ERROR_USAGE)
        quit(EXIT_CODE_ERROR)
    host_name = sys.argv[ARGS_HOST_IDX]
    controller_base_url = sys.argv[ARGS_CTRL_IDX]
    controller_auth_token = sys.argv[ARGS_TOKEN_IDX]


def is_iot_client(connection):
    if connection.get_dscp_value() == DSCP_NON_IOT:
        print(str(connection.get_tuple()) + ' NON-IOT')
        return False
    for entity in CACHE_CLIENTS['entities']:
        if entity['ip'] == connection.get_ip_src() and entity['dscp_value'] == connection.get_dscp_value():
            print(str(connection.get_tuple()) + ' CLIENT')
            return True
        print(str(connection.get_tuple()) + ' NON-CLIENT')
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
                        print(str(connection.get_tuple()) + ' VERIFIED')
                        break
            if connection_verified:
                break
        if not connection_verified:
            print(str(connection.get_tuple()) + ' NOT VERIFIED')
            action_block_connection(connection)
    add_to_connections_cache(connection)


def add_to_connections_cache(connection):
    CACHE_CONNECTION.append(connection.get_tuple())


def action_block_connection(connection):
    print('SHOULD BE BLOCKED')
    sdn_controller_web_driver = SdnControllerWebDriver(controller_base_url, controller_auth_token)
    sdn_controller_web_driver.block_connection(connection)


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
    if IP in pkt:
        connection = Connection(pkt[IP].src, pkt[IP].dst, tos_to_dscp_value(pkt[IP].tos))
        print('got a packet: ' + str(connection.get_tuple()))
        if is_iot_client(connection) and connection.get_tuple() not in CACHE_CONNECTION:
            print(str(connection.get_tuple()) + ' STARTED HANDLE')
            action_iot(connection)
        sys.stdout.flush()


if __name__ == '__main__':
    parse_arguments()
    print('Sniffing on %s' % host_name + '-' + IFACE)
    sys.stdout.flush()
    sniff(iface=host_name + '-' + IFACE, prn=lambda x: handle_pkt(x))
