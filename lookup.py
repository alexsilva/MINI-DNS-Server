import socket
import sqlite3
import threading
import time

__author__ = 'alex'


class DNSRating(object):
    """ benchmark of dns """
    DNS = [
        '209.244.0.3', '209.244.0.4',  # Level31
        '8.8.8.8', '8.8.4.4',  # Google2
        '84.200.69.80', '84.200.70.40',  # DNS.WATCH3
        '8.26.56.26', '8.20.247.20',  # Comodo Secure DNS
        '208.67.222.222', '208.67.220.220',  # OpenDNS Home4
        '156.154.70.1', '156.154.71.1',  # DNS Advantage
        '199.85.126.10', '199.85.127.10',  # Norton ConnectSafe5
        '81.218.119.11', '209.88.198.133',  # GreenTeamDNS6
        '195.46.39.39', '195.46.39.40',  # SafeDNS7
        '216.87.84.211', '208.115.243.35',  # OpenNIC8
        '199.5.157.131', '208.71.35.137',  # Public-Root9
        '208.76.50.50', '208.76.51.51',  # SmartViper
        '216.146.35.35', '216.146.36.36',  # Dyn
        '37.235.1.174', '37.235.1.177',  # FreeDNS10
        '89.233.43.71', '91.239.100.100',  # censurfridns.dk11
        '74.82.42.42',  # Hurricane Electric12
        '109.69.8.51'  # puntCAT13
    ]

    name = 'dsnraking.sqlite'

    SQL = '''
        INSERT OR REPLACE INTO DNS (ip, rating)
            VALUES (COALESCE((SELECT ip FROM DNS WHERE ip = "{ip}"), "{ip}"), "{rating}")
        '''

    lock = threading.RLock()

    def __init__(self, name=None):
        self.conn = sqlite3.connect(name or self.name, check_same_thread=False)
        self._create_tables()

    def _create_tables(self):
        cur = self.conn.cursor()

        # Create table
        cur.execute("CREATE TABLE IF NOT EXISTS DNS (ip text, rating real);")

        for ip in self.DNS:
            cur.execute(self.SQL.format(ip=ip, rating=0.0))

        self.conn.commit()
        cur.close()

    @property
    def best(self):
        with DNSRating.lock:
            cur = self.conn.cursor()

            # Create table
            cur.execute("SELECT ip FROM DNS ORDER BY rating ASC")
            best = cur.fetchone()

            self.conn.commit()
            cur.close()
        return best[0]

    def update(self, ip, rating):
        with DNSRating.lock:
            cur = self.conn.cursor()
            cur.execute(self.SQL.format(ip=ip, rating=rating))
            self.conn.commit()
            cur.close()


class DNSLookupException(Exception):
    """ Caused on failed lookup """
    pass


class DNSLookup(object):
    PORT = 53

    def __init__(self, packs, dnsrating):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dnsrating = dnsrating
        self.packs = packs

    @property
    def ip(self):
        data = self.resolve()
        return '.'.join([str(i) for i in data][-4:])

    @property
    def raw_ip(self):
        return self.resolve()

    def resolve(self):
        index = 1
        while index < 5:
            ip = self.dnsrating.best
            # noinspection PyBroadException
            try:
                before = time.time()
                self.sock.sendto(self.packs, (ip, self.PORT))
                data, dns = self.sock.recvfrom(1024)
                after = time.time()
                self.dnsrating.update(ip, after - before)
                return data
            except:
                self.dnsrating.update(ip, 5.0)
            index += 1
        raise DNSLookupException('DNSLookup - IP not found!')

