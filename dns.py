"""
Reference:
    http://code.activestate.com/recipes/491264-mini-fake-dns-server/
Edited:
    Alex Sandro
"""
import ipaddress
import socket
from threading import Thread, RLock
import lookup


class DNSQuery(object):
    IP_CACHE = {}
    lock = RLock()

    def __init__(self, data):
        self.data = data

        _type = (data[2] >> 3) & 15  # Opcode bits

        self.domain = self.get_domain(_type, data)
        self.ip = ''

    @staticmethod
    def get_domain(_type, data):
        domain = []
        if _type == 0:  # Standard query
            ini = 12
            lon = data[ini]
            while lon != 0:
                domain.append(str(data[ini + 1:ini + lon + 1], 'utf-8'))
                ini += lon + 1
                lon = data[ini]
        return '.'.join(domain)

    def look_up_ip(self):
        if not self.domain in DNSQuery.IP_CACHE:
            ip_addr = lookup.get_ip(self.data)
            with DNSQuery.lock:
                DNSQuery.IP_CACHE[self.domain] = ip_addr
        else:
            print('In cache', self.domain, DNSQuery.IP_CACHE[self.domain])
        return DNSQuery.IP_CACHE[self.domain]

    def response(self):
        self.ip = self.look_up_ip()

        if self.domain and self.ip:
            packet = self.data[:2] + b"\x81\x80"
            packet += self.data[4:6] + self.data[4:6] + b'\x00\x00\x00\x00'  # Questions and Answers Counts

            packet += self.data[12:]  # Original Domain Name Question
            packet += b'\xc0\x0c'  # Pointer to domain name

            packet += b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'  # Response type, ttl and resource data length -> 4 bytes
            packet += ipaddress.IPv4Address(self.ip).packed  # 4bytes of IP
        else:
            packet = lookup.get_raw(self.data)
            print('DNS Server fatal failed...')
        return packet


class DNSResolver(Thread):

    def __init__(self, udps, addr, data):
        super(DNSResolver, self).__init__()
        self.udps = udps
        self.addr = addr
        self.data = data

    def run(self):
        print("Request from: ", ':'.join([str(i) for i in self.addr]))

        dns_query = DNSQuery(self.data)
        self.udps.sendto(dns_query.response(), self.addr)

        print('Response: {0} -> {1}'.format(dns_query.domain, dns_query.ip))


if __name__ == '__main__':
    print('MINI - DNS Server, Listen at: [localhost] 127.0.0.1')

    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind(('127.0.0.1', 53))

    try:
        while True:
            data, addr = udps.recvfrom(1024)
            dns = DNSResolver(udps, addr, data)
            dns.start()
    except KeyboardInterrupt:
        pass
    finally:
        udps.close()
        input('Press enter...')
