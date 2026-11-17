#!/usr/bin/env python3
"""
Simulates ransomware-like lateral movement: one host rapidly contacts
many different destination hosts in quick succession, searching for
machines to spread to. This is the key signature distinguishing lateral
movement from a simple port scan (which targets one host, many ports).

Usage: python3 lateral_movement_sim.py <dst_ip1> <dst_ip2> <dst_ip3> ...
"""
import sys
import time
from scapy.all import IP, ICMP, TCP, send

if len(sys.argv) < 2:
    print("Usage: python3 lateral_movement_sim.py <dst_ip1> <dst_ip2> ...")
    sys.exit(1)

targets = sys.argv[1:]
print(f"Simulating lateral movement: probing {len(targets)} hosts rapidly")

for dst_ip in targets:
    # ICMP probe (checking if host is alive) + a TCP SYN probe (checking for open services)
    send(IP(dst=dst_ip) / ICMP(), verbose=False)
    send(IP(dst=dst_ip) / TCP(dport=445, flags="S"), verbose=False)  # 445 = SMB, classic ransomware spread port
    print(f"  Probed {dst_ip}")
    time.sleep(0.1)  # rapid, not evenly spaced like normal traffic

print("Lateral movement simulation complete.")
