"""
Reference:
    http://code.activestate.com/recipes/491264-mini-fake-dns-server/
Edited:
    Alex Sandro
"""
import argparse
import socket
from threading import Thread
import select

import ipaddress

from storage import Storage, Address
from lookup import DNSLookup, DNSRating, DNSLookupException


class DNSQuery(object):

    def __init__(self, data, storage, dnsrating):
        self.storage = storage
        self.data = data
        self.address = Address()
        self.dnsLookup = DNSLookup(data, dnsrating)
        self._domain = None

    @property
    def domain(self):
        if not self._domain:
            domain = []
            code = (self.data[2] >> 3) & 15  # Opcode bits
            if code == 0:  # Standard query
                ini = 12
                lon = self.data[ini]
                while lon != 0:
                    domain.append(str(self.data[ini + 1:ini + lon + 1], 'utf-8'))
                    ini += lon + 1
                    lon = self.data[ini]
            self._domain = '.'.join(domain)
        return self._domain

    def lookup(self):
        self.address = self.storage.find(self.domain)
        if not self.address.is_valid():
            try:
                self.address.domain = self.domain
                self.address.ip = self.dnsLookup.ip
            except DNSLookupException:
                self.address.ip = None
            else:
                self.storage.add(self.address.domain, self.address.ip)
            finally:
                self.address.expiration = 0.0
        return self.address

    def response(self):
        if self.lookup().is_valid():
            packet = self.data[:2] + b"\x81\x80"
            packet += self.data[4:6] + self.data[4:6] + b'\x00\x00\x00\x00'  # Questions and Answers Counts

            packet += self.data[12:]  # Original Domain Name Question
            packet += b'\xc0\x0c'  # Pointer to domain name

            packet += b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'  # Response type, ttl and resource data length -> 4 bytes
            packet += ipaddress.IPv4Address(self.address.ip).packed  # 4bytes of IP
        else:
            packet = self.dnsLookup.raw_ip
        return packet


class DNSResolver(Thread):
    def __init__(self, server, data, addr):
        super(DNSResolver, self).__init__()
        self.server = server
        self.addr = addr
        self.data = data

    def __getattr__(self, item):
        return getattr(self.server, item)

    def run(self):
        print("Request: {0!s}".format(':'.join([str(i) for i in self.addr])))
        try:
            query = DNSQuery(self.data, self.storage, self.dnsrating)
            self.server.sendto(query.response(), self.addr)
        except OSError:
            return  # closed by client
        print('Response[cache:{0!s}] {1!s}'.format(
            'yes' if query.address.is_valid() else 'no',
            query.address))


class DNSServer(object):
    def __init__(self, loc='127.0.0.1', port=53, **kwargs):
        self.loc = loc
        self.port = port

        self.storage = Storage(expiration=kwargs.pop('expiration', 0),
                               skip_ip_patterns=kwargs.pop('skip_ip_patterns', []))
        self.dnsrating = DNSRating()

        self.udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def __getattr__(self, item):
        return getattr(self.udps, item)

    def start(self, timeout=15):
        self.udps.bind((self.loc, self.port))
        while True:
            # noinspection PyBroadException
            try:
                rlist, wlist, xlist = select.select([self.udps], [], [], timeout)
                if rlist:
                    dns = DNSResolver(self, *rlist[0].recvfrom(1024))
                    dns.start()
            except KeyboardInterrupt:
                break
            except Exception as err:
                print(err)
                continue  # closed by client
        self.udps.close()
        print('Server stopped...')

    def __str__(self):
        return '{self.loc}:{self.port}'.format(self=self)


def main():
    parser = argparse.ArgumentParser(description='General settings of server and storage.')
    parser.add_argument('--socket-timeout', dest='socket_timeout', type=float, default=30.0,
                        help='Set the default timeout in floating seconds for new socket objects.')
    parser.add_argument('--loc', default='127.0.0.1', help='Ip address of the server (default 127.0.0.1).')
    parser.add_argument('--port', default=53, type=int, help='Sets communication port dns server (default 53).')
    parser.add_argument('--storage-expiration', default=300, type=int, dest='expiration',
                        help='Time in seconds in which new IPs addresses are stored in the database (default 300s).')
    parser.add_argument('--storage-skip-ip-patterns', nargs="*", dest='skip_ip_patterns',
                        help='Ignores the ips storage data by regular expressions.')
    args = parser.parse_args()

    socket.setdefaulttimeout(args.socket_timeout)
    server = DNSServer(loc=args.loc, port=args.port, expiration=args.expiration,
                       skip_ip_patterns=args.skip_ip_patterns)
    print('MINI - DNS Server, Listen at: {0!s}'.format(server))
    server.start()


if __name__ == '__main__':
    main()