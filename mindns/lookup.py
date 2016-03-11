import socket
import time

import dnslib

from mindns.storage import Address, MultiAddress

__author__ = 'alex'


class DNS(object):
    def __init__(self, *args):
        self.args = args

    @property
    def ip(self):
        try:
            return self.args[0]
        except IndexError:
            return None

    @property
    def rating(self):
        try:
            return self.args[1]
        except IndexError:
            return 0.0

    def __bool__(self):
        return bool(self.args)


class DNSRating(object):
    """ benchmark of dns """
    DNS = [
        '8.8.8.8', '8.8.4.4',  # Google2
        '209.244.0.3', '209.244.0.4',  # Level31
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

    def __init__(self, db):
        self.db = db
        self._create_tables()

    def __getattr__(self, name):
        return getattr(self.db, name)  # db alias

    def _create_tables(self):
        with self.lock:
            cur = self.conn.cursor()

            # Create table
            cur.execute("CREATE TABLE IF NOT EXISTS DNS (ip text, rating real);")

            if not bool(self.best):  # empty
                for ip in self.DNS:
                    cur.execute("INSERT INTO DNS (ip, rating) VALUES(?, ?)", (ip, 0.0))

            self.conn.commit()
            cur.close()

    @property
    def best(self):
        with self.lock:
            cur = self.conn.cursor()

            # Create table
            cur.execute("SELECT ip,rating FROM DNS ORDER BY rating ASC LIMIT 2;")
            items = cur.fetchone()

            cur.close()
        return DNS(*items) if items else DNS()

    def update(self, ip, rating):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("UPDATE DNS SET rating=? WHERE ip=?;", (rating, ip))
            self.conn.commit()
            cur.close()

    def __len__(self):
        return len(self.DNS)


class DNSLookupException(Exception):
    """ Caused on failed lookup """
    pass


class DNSLookup(object):
    PORT = 53

    def __init__(self, domain, packs, dnsrating):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dnsrating = dnsrating
        self.packs = packs
        self.domain = domain
        self._record = None

    @property
    def multiaddr(self):
        items = []
        for rr in self.record.rr:
            addr = Address(
                self.domain.strip("."),
                str(rr.rdata).strip("."),
                dnslib.QTYPE[rr.rtype],
                rclass=dnslib.CLASS[rr.rclass],
                ttl=rr.ttl)
            items.append(addr)
        return MultiAddress(items)

    @property
    def record(self):
        if self._record is not None:
            return self._record
        index = 1
        while index < len(self.dnsrating):
            best_dns = self.dnsrating.best

            if not bool(best_dns):
                continue

            # noinspection PyBroadException
            try:
                before = time.time()
                self.sock.sendto(self.packs, (best_dns.ip, self.PORT))
                self._record, dns = self.sock.recvfrom(1024)
                after = time.time()

                assert len(self._record) > 0

                self.dnsrating.update(best_dns.ip, (after - before))

                self._record = dnslib.DNSRecord.parse(self._record)

                assert any([str(rr.rdata) for rr in self._record.rr])

                return self._record
            except Exception as err:
                self.dnsrating.update(best_dns.ip, best_dns.rating + 0.1)  # bed rate
            index += 1
        raise DNSLookupException('IP not Found!')
