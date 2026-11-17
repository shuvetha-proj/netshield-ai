#!/usr/bin/env python3
"""
Generates repeated lateral-movement rounds from the host it is run on,
always touching all 3 other hosts (including Guest, whose contact attempt
still gets recorded even though it's blocked). Run once from each of
hr, fin, crit:

    hr   python3 /home/shuve/netshield-ai/generate_lateral_only.py
    fin  python3 /home/shuve/netshield-ai/generate_lateral_only.py
    crit python3 /home/shuve/netshield-ai/generate_lateral_only.py
"""
import random
import socket
import subprocess
import time
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LABEL_FILE = os.path.join(BASE_DIR, "current_label.txt")
LATERAL_SCRIPT = os.path.join(BASE_DIR, "lateral_movement_sim.py")

ALL_HOSTS_INCL_GUEST = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]

FLUSH_WAIT = 5
ROUNDS = 15


def get_my_ip():
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True)
        for ip in out.stdout.split():
            if ip in ALL_HOSTS_INCL_GUEST:
                return ip
    except Exception:
        pass
    return None


def set_label(label):
    with open(LABEL_FILE, "w") as f:
        f.write(label + "\n")


def main():
    my_ip = get_my_ip()
    if my_ip is None:
        my_ip = input("Enter this host's IP (e.g. 10.0.0.1): ").strip()

    targets = [ip for ip in ALL_HOSTS_INCL_GUEST if ip != my_ip]
    print(f"Running as source host: {my_ip}, targets: {targets}")

    set_label("lateral_movement")
    for i in range(ROUNDS):
        print(f"\n--- Lateral round {i+1}/{ROUNDS} ---")
        subprocess.run(["python3", LATERAL_SCRIPT] + targets)
        time.sleep(FLUSH_WAIT)

    print(f"\nDone. Generated {ROUNDS} lateral-movement rounds from {my_ip}.")


if __name__ == "__main__":
    main()
