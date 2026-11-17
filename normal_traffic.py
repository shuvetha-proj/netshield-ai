#!/usr/bin/env python3
"""Simulates normal traffic: periodic small pings to one destination."""
import sys
import time
from scapy.all import IP, ICMP, send

if len(sys.argv) < 2:
    print("Usage: python3 normal_traffic.py <dst_ip> [count] [interval]")
    sys.exit(1)

dst_ip = sys.argv[1]
count = int(sys.argv[2]) if len(sys.argv) > 2 else 20
interval = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0

print(f"Sending {count} normal pings to {dst_ip} every {interval}s")
for i in range(count):
    pkt = IP(dst=dst_ip) / ICMP()
    send(pkt, verbose=False)
    time.sleep(interval)

print("Done.")
