import socket
import sqlite3
import threading
import time
import re

__author__ = 'alex'


class Address(object):
    def __init__(self, domain=None, ip=None, expiration=0.0):
        self.domain = domain
        self.ip = ip
        self.expiration = expiration

    @staticmethod
    def _validate_ip(ip):
        try:
            valid = socket.inet_aton(ip)
        except socket.error:
            valid = None
        return bool(valid)

    @property
    def time(self):
        return self.expiration - time.time()

    def is_valid(self):
        return bool(self.domain and self._validate_ip(self.ip) and self.expiration)

    def __str__(self):
        return '[{0.ip}] {0.domain} {0.time:.2f}s'.format(self)


class Storage(object):
    lock = threading.RLock()

    name = 'iptables.sqlite'

    expiration = 300

    def __init__(self, name=None, expiration=0, skip_ip_patterns=[]):
        self.conn = sqlite3.connect(name or self.name, check_same_thread=False)
        self.expiration = expiration or self.expiration
        self.skip_ip_patterns = [re.compile(p) for p in skip_ip_patterns]
        self._create_tables()

    def cleanup(self, cur):
        cur.execute('DELETE FROM IP WHERE expiration<?;', (time.time() - self.expiration,))

    def _create_tables(self):
        cur = self.conn.cursor()

        # Create table
        cur.execute('CREATE TABLE IF NOT EXISTS IP (domain text, ip text, expiration real);')

        self.conn.commit()
        cur.close()

    def find(self, domain):
        with Storage.lock:
            cur = self.conn.cursor()
            self.cleanup(cur)

            cur.execute('SELECT * FROM IP WHERE domain=? AND expiration>=?;', (domain, time.time()))

            args = cur.fetchone()
            cur.close()

        return Address(*(args or ()))

    def add(self, domain, ip):
        for pattern in self.skip_ip_patterns:
            if pattern.match(ip):
                return
        with Storage.lock:
            cur = self.conn.cursor()
            self.cleanup(cur)

            expiration = time.time() + self.expiration
            cur.execute('INSERT INTO IP(domain, ip, expiration) VALUES (?, ?, ?);', (domain, ip, expiration))

            self.conn.commit()
            cur.close()

            return Address(domain, ip, expiration)