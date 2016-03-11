#! /usr/bin/env python3

from __future__ import print_function

import argparse
import os
import socket
import sys

from mindns.dns import SharedDB, DNSServer


def detach(stdout="/dev/null", stderr=None, stdin="/dev/null", pidfile=None):
    """This forks the current process into a daemon.

    The stdin, stdout, and stderr arguments are file names that
    will be opened and be used to replace the standard file descriptors
    in sys.stdin, sys.stdout, and sys.stderr.

    These arguments are optional and default to /dev/null.

    Note that stderr is opened unbuffered, so if it shares a file with
    stdout then interleaved output may not appear in the order that you
    expect."""
    # Do first fork.
    try:
        pid = os.fork()
        if pid > 0:
            # Exit first parent.
            sys.exit(0)
    except OSError as err:
        print("Fork #1 failed: (%d) %s" % (err.errno, err.strerror),
              file=sys.stderr)
        sys.exit(1)

    # Decouple from parent environment.
    os.chdir("/")
    os.umask(0)
    os.setsid()

    # Do second fork.
    try:
        pid = os.fork()
        if pid > 0:
            # Exit second parent.
            sys.exit(0)
    except OSError as err:
        print("Fork #2 failed: (%d) %s" % (err.errno, err.strerror),
              file=sys.stderr)
        sys.exit(1)

    # Open file descriptors and print start message.
    if not stderr:
        stderr = stdout
    stdi = open(stdin, "r")
    stdo = open(stdout, "a+")
    stde = open(stderr, "ab+", 0)
    pid = str(os.getpid())
    if pidfile:
        with open(pidfile, "w+") as pidf:
            pidf.write("%s\n" % pid)

    # Redirect standard file descriptors.
    os.dup2(stdi.fileno(), sys.stdin.fileno())
    os.dup2(stdo.fileno(), sys.stdout.fileno())
    os.dup2(stde.fileno(), sys.stderr.fileno())


def main():
    parser = argparse.ArgumentParser(
        description='General settings of server and storage.')
    parser.add_argument('--socket-timeout', dest='socket_timeout', type=float,
                        default=5.0,
                        help='Set the default timeout in floating seconds for '
                             'new socket objects.')
    parser.add_argument('--loc', default='127.0.0.1',
                        help='Ip address of the server (default 127.0.0.1).')
    parser.add_argument('--port', default=53, type=int,
                        help='Sets communication port dns server (default 53).')

    logstdout_parser = parser.add_mutually_exclusive_group(required=False)
    logstdout_parser.add_argument('--log-stdout', dest='log_stdout', action='store_true',
                        help='Prints messages to standard output (stdout).')
    logstdout_parser.add_argument('--no-log-stdout', dest='log_stdout', action='store_false',
                        help='Redirect messages to the log file.')
    parser.set_defaults(log_stdout=True)

    parser.add_argument('--log-filepath', default="mindns.log", type=str, dest='log_filepath',
                        help='Sets the path for the logger file (if --log-stdout = False)'),

    parser.add_argument('--db-filepath', default=SharedDB.filename, type=str,
                        dest='db_filepath',
                        help='Defines the location of the given database file '
                             '(full path).')
    parser.add_argument('--storage-skip-ip-patterns', default=[], nargs="*",
                        dest='skip_ip_patterns',
                        help='Ignores the ips storage data by regular '
                             'expressions.')
    parser.add_argument("--detach", default=False, dest="detach",
                        action="store_true",
                        help="Daemonize and detach the server.")
    parser.add_argument("--pid-file", dest="pidfile",
                        default="/var/lib/mdns.pid",
                        help="Store the PID in this file.")
    args = parser.parse_args()
    socket.setdefaulttimeout(args.socket_timeout)
    server = DNSServer(loc=args.loc, port=args.port,
                       db_filepath=args.db_filepath,
                       skip_ip_patterns=args.skip_ip_patterns,
                       log_stdout=args.log_stdout,
                       log_filepath=args.log_filepath)
    server.logger.info('MINI - DNS Server, Listen at: {0!s}'.format(server))
    if args.detach:
        detach(pidfile=args.pidfile)
    try:
        server.start()
    finally:
        try:
            os.remove(args.pidfile)
        except:
            pass


if __name__ == '__main__':
    main()
