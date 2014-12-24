import socket

__author__ = 'alex'

dns_server = ('8.8.8.8', 53)


class DNSLookup(object):

    def __init__(self, packs):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.packs = packs

    @property
    def ip(self):
        data = self.resolve()
        return '.'.join([str(i) for i in data][-4:])

    @property
    def raw_ip(self):
        return self.resolve()

    def resolve(self):
        self.sock.sendto(self.packs, dns_server)
        data, dns = self.sock.recvfrom(1024)
        return data

