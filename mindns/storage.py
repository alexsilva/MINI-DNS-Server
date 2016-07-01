import re
import time

import dnslib

import mindns.utils as utils

__author__ = 'alex'

# alias
qtype = dnslib.QTYPE.reverse
_class = dnslib.CLASS.reverse


class Address(object):
    def __init__(self, domain=None, ip=None, rtype=None, rclass=None, ttl=0, counter=0, dns_name=''):
        self.domain = domain
        self.ip = ip
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = int(ttl)
        self.counter = counter
        self.dns_name = dns_name

    @property
    def time(self):
        return int(self.counter - time.time())

    @property
    def ttl_now(self):
        return self.time

    @property
    def expired(self):
        return self.time <= 0

    def is_valid(self):
        return bool(self.domain and utils.validate_ip(self.ip) and not self.expired)

    def __str__(self):
        return '{0.dns_name}|{0.ip}|{0.domain}|{0.ttl}s|{0.time}s'.format(self)


class MultiAddress(Address):

    def __init__(self, items=None):
        if items is None:
            items = []
        self.items = items

    def is_valid(self):
        return any([address.is_valid() for address in self.items])

    def __iter__(self):
        return iter(self.items)

    def __str__(self):
        return '\n'.join([str(x) for x in self.items])

    def __len__(self):
        return len(self.items)


class Storage(object):

    def __init__(self, db, skip_ip_patterns=[]):
        self.db = db
        self.skip_ip_patterns = [re.compile(p) for p in skip_ip_patterns]
        self._create_tables()

    def __getattr__(self, name):
        return getattr(self.db, name)  # db alias

    def cleanup(self, cur):
        cur.execute('DELETE FROM IP WHERE counter<?;', (time.time(),))
        self.conn.commit()

    def _create_tables(self):
        with self.lock:
            cur = self.conn.cursor()

            # Create table
            cur.execute('CREATE TABLE IF NOT EXISTS IP (domain text, ip text PRIMARY KEY, '
                        'rtype text, rclass text, ttl real, counter real, dns_name text);')

            self.conn.commit()
            cur.close()

    def find(self, domain):
        with self.lock:
            cur = self.conn.cursor()
            self.cleanup(cur)

            cur.execute('SELECT * FROM IP WHERE domain=? AND counter>?;', (domain, time.time()))
            multiaddr = MultiAddress([Address(*(args or ())) for args in cur.fetchall()])

            cur.close()
        return multiaddr

    def add(self, domain, ip, rtype, rclass, ttl, dns):
        for pattern in self.skip_ip_patterns:
            if pattern.match(ip):
                return Address()
        with self.lock:
            cur = self.conn.cursor()
            self.cleanup(cur)

            addr = Address(domain, ip, rtype, rclass, ttl, time.time() + ttl)

            cur.execute('INSERT OR REPLACE INTO IP (domain, ip, rtype, rclass, ttl, counter, dns_name) '
                        'VALUES (?,?,?,?,?,?,?);', (
                            addr.domain, addr.ip, addr.rtype,
                            addr.rclass, addr.ttl, addr.counter,
                            dns.name)
                        )
            self.conn.commit()
            cur.close()

            return addr
