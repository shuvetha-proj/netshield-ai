#!/usr/bin/env python3
"""Simulates scan-like traffic: rapid SYN packets to many ports on one host,
mimicking ransomware probing for open shares/services before spreading."""
import sys
from scapy.all import IP, TCP, send

if len(sys.argv) < 2:
    print("Usage: python3 scan_sim.py <dst_ip> [start_port] [end_port]")
    sys.exit(1)

dst_ip = sys.argv[1]
start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 100

print(f"Scanning {dst_ip} ports {start_port}-{end_port}")
for port in range(start_port, end_port + 1):
    pkt = IP(dst=dst_ip) / TCP(dport=port, flags="S")
    send(pkt, verbose=False)

print("Scan complete.")
