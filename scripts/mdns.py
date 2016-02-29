#! /usr/bin/env python3
import argparse
import socket

from mindns.dns import SharedDB, DNSServer


def main():
    parser = argparse.ArgumentParser(description='General settings of server and storage.')
    parser.add_argument('--socket-timeout', dest='socket_timeout', type=float, default=5.0,
                        help='Set the default timeout in floating seconds for new socket objects.')
    parser.add_argument('--loc', default='127.0.0.1', help='Ip address of the server (default 127.0.0.1).')
    parser.add_argument('--port', default=53, type=int, help='Sets communication port dns server (default 53).')
    parser.add_argument('--db-filepath', default=SharedDB.filename, type=str, dest='db_filepath',
                        help='Defines the location of the given database file (full path).')
    parser.add_argument('--storage-skip-ip-patterns', default=[], nargs="*", dest='skip_ip_patterns',
                        help='Ignores the ips storage data by regular expressions.')
    args = parser.parse_args()
    socket.setdefaulttimeout(args.socket_timeout)
    server = DNSServer(loc=args.loc, port=args.port, db_filepath=args.db_filepath,
                       skip_ip_patterns=args.skip_ip_patterns)
    print('MINI - DNS Server, Listen at: {0!s}'.format(server))
    server.start()


if __name__ == '__main__':
    main()
