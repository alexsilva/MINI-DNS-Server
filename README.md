MINI-DNS-Server
===============

MINI DNS Server: Resolve domain names and saves the ips in a database (cache).

Uses an internal list of the best current dns servers.
When a server responds correctly, your rating is close to zero and this causes it to be used in the next interactions.
Not always a dns server responds correctly, it causes another to be used in place of what was best.

Works on Python 3.2+
