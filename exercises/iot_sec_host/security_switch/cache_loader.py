import json

CACHE_FILE_DNS = './cache/dns_cache.json'
CACHE_FILE_MUD = './cache/mud_cache.json'


def load_cache_dns():
    return load_json_file(CACHE_FILE_DNS)


def load_cache_mud():
    return load_json_file(CACHE_FILE_MUD)


def load_json_file(file_path):
    with open(file_path) as file:
        data = json.load(file)
    return data
