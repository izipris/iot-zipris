class Connection:
    def __init__(self, ip_src, ip_dst, dscp_value):
        self.__ip_src = ip_src
        self.__ip_dst = ip_dst
        self.__dscp_value = dscp_value

    def get_ip_src(self):
        return self.__ip_dst

    def get_ip_dst(self):
        return self.__ip_dst

    def get_dscp_value(self):
        return self.__dscp_value
