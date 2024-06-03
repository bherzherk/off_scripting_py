#!/usr/bin/env python3
import scapy.all as scapy
import argparse

def get_argument():
    parser = argparse.ArgumentParser(description="DNS Sniffer, intercept DNS")
    parser.add_argument("-i", "--interface", required=True, dest="interface", help="interface ens33/eth0")

    args = parser.parse_args()

    return args.interface

def process_dns_packet(packet):
    if packet.haslayer(scapy.DNSQR):
        domain = packet[scapy.DNSQR].qname.decode()

        exclude_keywords = ["google", "cloud", "static"]

        if domain not in domains_seen and not any(keyword in domain for keyword in exclude_keywords):
            domains_seen.add(domain)
            print(f"[+] Domain: {domain}")

def sniff(interface):
    scapy.sniff(iface=interface, filter="udp and port 53", prn=process_dns_packet, store=0)

def run_sniffer():
    interface = get_argument()
    sniff(interface)

if __name__ == "__main__":
    global domains_seen
    domains_seen = set()

    run_sniffer()
