"""
Reference:
    http://code.activestate.com/recipes/491264-mini-fake-dns-server/
Edited:
    Alex Sandro
"""
import logging
import os
import select
import socket
import sqlite3
import sys
import threading
from logging.handlers import RotatingFileHandler
from threading import Thread

import dnslib

import mindns.utils as utils
from mindns.lookup import DNSLookup, DNSRating, DNSLookupException
from mindns.storage import Storage, MultiAddress

# alias
qtype = dnslib.QTYPE.reverse
_class = dnslib.CLASS.reverse


class DNSQuery(object):
    def __init__(self, data, storage, dnsrating):
        self.storage = storage
        self.data = data
        self.multiaddr = MultiAddress()
        self._domain = self._record = None
        self.dnsLookup = DNSLookup(self.domain, data, dnsrating)

    @property
    def domain(self):
        if not self._domain:
            self._record = dnslib.DNSRecord.parse(self.data)
            self._domain = str(self._record.questions[0].qname).strip(".")
        return self._domain

    def lookup(self):
        self.multiaddr = self.storage.find(self.domain)
        if not self.multiaddr.is_valid():
            try:
                self.multiaddr = self.dnsLookup.multiaddr
                for address in self.dnsLookup.multiaddr:
                    self.storage.add(address.domain,
                                     address.ip,
                                     address.rtype,
                                     address.rclass,
                                     address.ttl,
                                     self.dnsLookup.bdns)
            except DNSLookupException:
                pass
        return self.multiaddr

    def response(self):
        if self.lookup().is_valid():
            record = dnslib.DNSRecord(
                dnslib.DNSHeader(id=self._record.header.id, qr=1, rd=1, ra=1),
                q=dnslib.DNSQuestion(self.domain)
            )
            for address in self.multiaddr:
                answer = dnslib.RR(address.domain,
                                   ttl=address.ttl_now,
                                   rtype=qtype[address.rtype],
                                   rclass=_class[address.rclass],
                                   rdata=getattr(dnslib, address.rtype)(address.ip))
                record.add_answer(answer)
            packs = record.pack()
        else:
            try:
                packs = self.dnsLookup.record.pack()
            except DNSLookupException:
                return b''
        return packs


class DNSResolver(Thread):
    def __init__(self, server, data, addr):
        super(DNSResolver, self).__init__()
        self.server = server
        self.addr = addr
        self.data = data

    def __getattr__(self, item):
        return getattr(self.server, item)

    def __str__(self):
        return "{0.addr[0]}:{0.addr[1]}".format(self)

    def run(self):
        self.logger.info("Request from {0!s}".format(self))

        query = DNSQuery(self.data, self.storage, self.dnsrating)
        self.server.sendto(query.response(), self.addr)

        self.logger.info('Client({0!s}) response[{1:s}]\n{2!s}'.format(self,
            'cached' if query.multiaddr.is_valid() else 'no cache',
            query.multiaddr))


class SharedDB(object):
    """Database for storage ips and dns servers"""
    lock = threading.RLock()
    filename = 'dns_server.sqlite'
    version = 3

    def __init__(self, filepath=None):
        if os.path.isdir(filepath):
            filepath = os.path.join(filepath, self.filename)
        self._conn = sqlite3.connect(
            utils.versioned_filepath(filepath or self.filename, self.version),
            check_same_thread=False)

    @property
    def conn(self):
        """public access"""
        return self._conn


class DNSServer(object):
    def __init__(self, loc='127.0.0.1', port=53, **kwargs):
        self.loc = loc
        self.port = port

        log_stdout = kwargs.pop('log_stdout', True)
        log_filepath = kwargs.pop('log_stdout', "mindns.log")

        self.shared_db = SharedDB(kwargs.pop('db_filepath'))
        self.storage = Storage(self.shared_db, skip_ip_patterns=kwargs.pop('skip_ip_patterns', []))
        self.dnsrating = DNSRating(self.shared_db)

        self.udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # LOGGER
        self.logger = self._get_logger(log_stdout, log_filepath)

    def _get_logger(self, log_stdout, log_filepath):
        """Configuration of logger"""
        logger = logging.getLogger("%s:%d" % (self.loc, self.port))
        if log_stdout:
            handler = logging.StreamHandler(sys.stdout)
        else:
            handler = RotatingFileHandler(log_filepath)
        handler.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        return logger

    def __getattr__(self, item):
        return getattr(self.udps, item)

    def start(self, timeout=15):
        self.udps.bind((self.loc, self.port))
        while True:
            # noinspection PyBroadException
            try:
                rlist, wlist, xlist = select.select([self.udps], [], [], timeout)
                data, addr = rlist[0].recvfrom(1024)
            except (ConnectionResetError, IndexError):
                continue
            except KeyboardInterrupt:
                break
            except Exception as err:
                self.logger.error("Server error {0!s}".format(err))
                continue
            try:
                dns = DNSResolver(self, data, addr)
                dns.start()
            except Exception as err:
                self.logger.error("Client error {0!s}".format(err))
        self.udps.close()
        self.logger.info('Server stopped...')

    def __str__(self):
        return '{self.loc}:{self.port}'.format(self=self)
