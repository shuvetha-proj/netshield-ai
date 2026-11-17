#!/usr/bin/env python3
"""
Simulates ransomware-like lateral movement with VARIABLE traffic volume.
Still contacts all targets (fan-out signature preserved), but each run sends a
RANDOM number of probe rounds at RANDOM intervals, so the captured traffic
volume and timing differ every time — more realistic, while the detection
signature (fan-out + ICMP/TCP mix) stays consistent.

Usage: python3 lateral_movement_sim.py <dst_ip1> <dst_ip2> ...
"""
import sys
import time
import random
from scapy.all import IP, ICMP, TCP, send

if len(sys.argv) < 2:
    print("Usage: python3 lateral_movement_sim.py <dst_ip1> <dst_ip2> ...")
    sys.exit(1)

targets = sys.argv[1:]

rounds = random.randint(2, 5)
print(f"Simulating lateral movement: probing {len(targets)} hosts "
      f"over {rounds} round(s) with variable timing")

for r in range(rounds):
    for dst_ip in targets:
        send(IP(dst=dst_ip) / ICMP(), verbose=False)
        send(IP(dst=dst_ip) / TCP(dport=445, flags="S"), verbose=False)
        time.sleep(random.uniform(0.05, 0.25))
    if r < rounds - 1:
        time.sleep(random.uniform(0.2, 0.6))

print(f"Lateral movement simulation complete ({rounds} rounds).")
