#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse
import socket
import collections
import threading
import sys
import os
import select
import tty
import termios
import atexit
import datetime
import signal
from datetime import datetime as dt
from os.path import expanduser, abspath
from interfaces import get_udp_broadcast_addrs


BACKEND_PORT = 2025
BackendServer = collections.namedtuple("BackendServer", ["name", "addr", "backends"])
Backend = collections.namedtuple("Backend", ["name", "type", "user", "time"])


def get_connection_string(command, username=None, server="", backend_class=""):
    if username is None:
        username = os.getenv("USER", "xkdb-user")

    string = bytearray(b"\0" * 50)

    string[0] = b"C"
    if command == "list":
        string[1] = chr(4)
    elif command == "connect":
        string[1] = chr(9)
    else:
        raise ValueError("invalid command")

    string[2 : 2 + len(username)] = username.encode("utf8")
    string[18 : 18 + len(server)] = server.encode("utf8")
    string[34 : 34 + len(backend_class)] = backend_class.encode("utf8")

    return bytes(string)


# Gets a string up to a null terminator, returning the length advanced
def get_string(s):
    string = bytearray()
    count = 0
    for char in s:
        count += 1
        if char == 0 or char == "\0":
            break
        string.append(char)

    string = string.decode("utf8")
    return string, count


def parse_backend_response(response):
    if len(response) < 76:
        raise ValueError("Invalid response size")
    if response[0] != b"C":
        raise ValueError("Invalid response version")
    backends = []

    server_name = response[2:65].replace(b"\0", b"").decode("utf8")

    num_backends = response[66:75].replace(b"\0", b"").decode("utf8")
    num_backends = int(num_backends)

    read_cursor = 76
    for i in range(num_backends):
        backend_name, length = get_string(response[read_cursor:])
        read_cursor += length
        backend_type, length = get_string(response[read_cursor:])
        read_cursor += length

        # if the backend has a user connected
        if response[read_cursor] != b"\0":
            read_cursor += 1
            user, length = get_string(response[read_cursor:])
            read_cursor += length
            time, length = get_string(response[read_cursor:])
            read_cursor += length
        else:
            read_cursor += 1
            user = None
            time = None

        b = Backend(backend_name, backend_type, user, time)
        backends.append(b)

    return server_name, backends


def parse_port(response):
    if response[0:1] != b"C":
        raise ValueError("Invalid response version")

    server_name = response[2:65].replace(b"\0", b"").decode("utf8")
    port = response[76:]
    port = port.split()
    port = int(port[0])

    return port


def get_free_backend(backend_servers):
    for server in backend_servers:
        for backend in server.backends:
            if backend.user is None:
                return server, backend
    return None, None


def get_specific_backend(backend_servers, backend_name):
    for server in backend_servers:
        for backend in server.backends:
            if backend.name == backend_name:
                return server, backend
    return None, None


def get_backend_servers(backend_class="cortex"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    s.bind(("0.0.0.0", 0))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 40000)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    addresses = get_udp_broadcast_addrs()
    backend_servers = []

    connection_string = get_connection_string(
        command="list", backend_class=backend_class
    )
    for address in addresses:
        s.sendto(connection_string, (address, BACKEND_PORT))
        response, addr = s.recvfrom(125004)
        server_name, backends = parse_backend_response(response)

        backend_server = BackendServer(server_name, addr[0], backends)
        backend_servers.append(backend_server)

    # Close the udp socket
    s.close()
    return backend_servers


def send_command(addr, command):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    sock.sendto(command, (addr, BACKEND_PORT))

    response, addr = sock.recvfrom(125004)
    sock.close()
    return response, addr


# Powercycles a backend connected to a Xinu server at addr
def powercycle(addr, backend):
    connection_string = get_connection_string(
        command="connect", server=backend.name + "-pc", backend_class="POWERCYCLE"
    )
    response, addr = send_command(addr, connection_string)
    port = parse_port(response)

    # Establish a tcp connection on the provided port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((addr[0], port))
    s.send("boop")
    s.shutdown(socket.SHUT_WR)
    s.close()


def upload_image(addr, backend, image_file):
    connection_string = get_connection_string(
        command="connect", server=backend.name + "-dl", backend_class="DOWNLOAD"
    )
    response, addr = send_command(addr, connection_string)
    port = parse_port(response)

    # Establish a tcp connection on the provided port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((addr[0], port))

    # Read file and send in chunks of size 4096
    chunk = image_file.read(4096)
    while chunk != "":
        s.send(chunk)
        chunk = image_file.read(4096)
    s.shutdown(socket.SHUT_WR)
    s.close()


def alarm_handler(signum, frame):
    raise Exception("Timout.")


def main():
    parser = argparse.ArgumentParser(
        description="Connect to a XINU backend and run an image."
    )
    parser.add_argument(
        "--class",
        "-c",
        dest="type",
        action="store",
        help="the type of backend board to connect to (default=quark)",
    )
    parser.add_argument(
        "--xinu",
        "-x",
        dest="xinu_file",
        action="store",
        default="xinu.xbin",
        help="the xinu image file to upload and debug\n" '(default="./xinu")',
    )
    parser.add_argument(
        "--log",
        "-l",
        dest="log",
        action="store",
        help="The name of the file to log to.",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        dest="timeout",
        action="store",
        type=int,
        default=30,
        help="Timeout to run for in seconds",
    )
    parser.add_argument(
        "backend",
        metavar="BACKEND",
        type=str,
        nargs="?",
        default=None,
        help="optionally specify a backend board to connect to",
    )
    args = parser.parse_args()

    if args.timeout:
        signal.signal(signal.SIGALRM, alarm_handler)
        signal.alarm(args.timeout)

    if args.log:
        logfile = open(args.log, "w")
    else:
        logfile = None

    if not args.backend:
        print("Must specify a backend!")
        exit(1)

    backend_type = args.type
    if not backend_type:
        backend_type = os.environ.get(
            "CS_CLASS", "quark"
        )  # Default to 'quark' if CS_CLASS does not exist

    backend_servers = get_backend_servers(backend_class=backend_type)

    server, backend = get_specific_backend(backend_servers, args.backend)
    if server is None:
        print("Backend {} not found.".format(args.backend))
        return

    if backend.user is not None:
        print("Backend {} is in use by {}".format(backend.name, backend.user))
        return

    print("Uploading image file")
    with open(args.xinu_file, "rb") as f:
        upload_image(server.addr, backend, f)
    print("Done uploading image")

    connection_string = get_connection_string(
        command="connect", server=backend.name, backend_class=backend.type
    )
    response, addr = send_command(server.addr, connection_string)
    addr = addr[0]
    port = parse_port(response)

    print(
        "Connecting to {}, backend: {}, address: {}:{}".format(
            server.name, backend.name, addr, port
        )
    )

    # Establish a tcp connection on the provided port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((addr, port))
    xinu_sock = s.makefile("rb", 0)

    print("[i] Power cycling backend")
    powercycle(server.addr, backend)

    starttime = dt.now()

    # perserve previous terminal settings
    fd = sys.stdin.fileno()
    prev_settings = termios.tcgetattr(fd)

    # set terminal to raw mode for stdin
    tty.setcbreak(sys.stdin)
    # register an exit handler for resetting the terminal
    atexit.register(lambda: termios.tcsetattr(fd, termios.TCSADRAIN, prev_settings))

    log = False
    buf = ""
    LOOK_FOR = "Xinu for galileo"
    while True:
        try:
            # poll to see if there is user input
            (read_in, _, _) = select.select([xinu_sock, sys.stdin], [], [])

            # handle stdin
            if sys.stdin in read_in:
                user_input = sys.stdin.read(1)
                xinu_sock.write(user_input)

            # handle socket
            elif xinu_sock in read_in:
                byte = xinu_sock.read(1)
                if not log:
                    buf += byte
                    if LOOK_FOR in buf:
                        log = True
                        if args.log:
                            logfile.write(LOOK_FOR)

                if log and args.log:
                    logfile.write(byte)
                else:
                    sys.stdout.write(byte)
                    sys.stdout.flush()
        except Exception as e:
            print(e)
            break

    if logfile is not None:
        logfile.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        print("TODO: implement exiting here...")
        pass
