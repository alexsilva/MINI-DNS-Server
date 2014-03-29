import socket

__author__ = 'alex'

dns_server = ('8.8.8.8', 53)


def get_ip(packs):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.sendto(packs, dns_server)
    data, dns = sock.recvfrom(1024)

    return '.'.join([str(i) for i in data][-4:])


def get_raw(packs):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.sendto(packs, dns_server)
    data, dns = sock.recvfrom(1024)

    return data

