"""
Reference:
    http://code.activestate.com/recipes/491264-mini-fake-dns-server/
Edited:
    Alex Sandro
"""
import socket
from threading import Thread, RLock
import select

import ipaddress

from storage import Storage, Address
from lookup import DNSLookup


class DNSQuery(object):
    lock = RLock()

    def __init__(self, data, storage):
        self.storage = storage
        self.data = data
        self.address = Address()
        self.dnsLookup = DNSLookup(data)
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
        with DNSQuery.lock:
            self.address = self.storage.find(self.domain)

        if not self.address.is_valid():
            self.address.ip = self.dnsLookup.ip

            with DNSQuery.lock:
                self.storage.add(self.domain, self.address.ip)
        else:
            print('In cache {0!s}'.format(self.address))
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
            print('DNS Server fatal failed...')
        return packet


class DNSResolver(Thread):
    def __init__(self, server, data, addr):
        super(DNSResolver, self).__init__()
        self.server = server
        self.addr = addr
        self.data = data

    def run(self):
        print("Request: {0!s}".format(':'.join([str(i) for i in self.addr])))
        try:
            query = DNSQuery(self.data, self.server.storage)
            self.server.sendto(query.response(), self.addr)
        except OSError:
            return  # closed by client
        print('Response: {0!s}'.format(query.address))


class DNSServer(object):
    def __init__(self, loc='127.0.0.1', port=53):
        self.loc = loc
        self.port = port

        self.storage = Storage()
        self.storage.create_tables()

        self.udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def __getattr__(self, item):
        return getattr(self.udps, item)

    def start(self):
        self.udps.bind((self.loc, self.port))

    def loop(self, timeout=15):
        try:
            while True:
                # noinspection PyBroadException
                try:
                    rlist, wlist, xlist = select.select([self.udps], [], [], timeout)
                    if rlist:
                        dns = DNSResolver(self, *rlist[0].recvfrom(1024))
                        dns.start()
                except Exception as err:
                    print(err)
                    continue  # closed by client
        except KeyboardInterrupt:
            pass
        finally:
            self.udps.close()
            input('Press enter...')

    def __str__(self):
        return '{self.loc}:{self.port}'.format(self=self)


def main():
    server = DNSServer()
    server.start()

    print('MINI - DNS Server, Listen at: {0!s}'.format(server))

    server.loop()


if __name__ == '__main__':
    main()