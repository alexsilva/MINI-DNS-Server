import sqlite3
import time

__author__ = 'alex'


class IP(object):

    def __init__(self, domain=None, address=None, expiration=0.0):
        self.domain = domain
        self.address = address
        self.expiration = expiration

    def valid(self):
        return bool(self.domain and self.address)


class Storage(object):

    name = 'iptables.sqlite'

    expiration = 300

    def __init__(self, name=None, expiration=0):
        self.conn = sqlite3.connect(name or self.name)
        self.expiration = expiration or self.__class__.expiration

    def create_tables(self):
        cur = self.conn.cursor()

        # Create table
        cur.execute('''CREATE TABLE IF NOT EXISTS IP (domain text, ip text, expiration real)''')

        self.conn.commit()
        cur.close()

    def find(self, domain):
        cur = self.conn.cursor()

        cur.execute('''SELECT domain, ip FROM IP WHERE domain=? AND expiration>=?''', (domain, time.time()))

        args = cur.fetchone()

        cur.close()

        return IP(*(args or ()))

    def add(self, domain, ip):
        cur = self.conn.cursor()

        cur.execute('''INSERT INTO IP(domain, ip, expiration) VALUES (?, ?, ?)''', (
            domain, ip, time.time() + self.expiration))

        self.conn.commit()
        cur.close()