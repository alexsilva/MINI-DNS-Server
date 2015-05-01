import time
import re


__author__ = 'alex'


class Address(object):
    def __init__(self, domain=None, ip=None, expiration=0.0):
        self.domain = domain
        self.ip = ip
        self.expiration = expiration

    @property
    def time(self):
        return self.expiration - time.time()

    def is_valid(self):
        return bool(self.domain and self.time > 0)

    def __str__(self):
        domain = '-1.-1.-1.-1' if not self.domain else self.domain
        return '[{0.ip}] {1} {0.time:.2f}s'.format(self, domain)


class Storage(object):

    def __init__(self, db, skip_ip_patterns=[]):
        self.db = db
        self.skip_ip_patterns = [re.compile(p) for p in skip_ip_patterns]
        self._create_tables()

    def __getattr__(self, name):
        return getattr(self.db, name)  # db alias

    def cleanup(self, cur):
        cur.execute('DELETE FROM IP WHERE expiration<?;', (time.time(),))
        self.conn.commit()

    def _create_tables(self):
        cur = self.conn.cursor()

        # Create table
        cur.execute('CREATE TABLE IF NOT EXISTS IP (domain text PRIMARY KEY, ip text, expiration real);')

        self.conn.commit()
        cur.close()

    def find(self, domain):
        with self.lock:
            cur = self.conn.cursor()
            self.cleanup(cur)

            cur.execute('SELECT * FROM IP WHERE domain=? AND expiration>?;', (domain, time.time()))

            args = cur.fetchone()
            cur.close()

        return Address(*(args or ()))

    def add(self, domain, ip, expiration):
        for pattern in self.skip_ip_patterns:
            if pattern.match(ip):
                return Address()
        with self.lock:
            cur = self.conn.cursor()
            self.cleanup(cur)

            expiration = time.time() + expiration  # future
            cur.execute('INSERT OR REPLACE INTO IP (domain, ip, expiration) VALUES (?,?,?);', (domain, ip, expiration))

            self.conn.commit()
            cur.close()

            return Address(domain, ip, expiration)