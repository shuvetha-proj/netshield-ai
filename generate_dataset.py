#!/usr/bin/env python3
"""
Driver script: generates many varied rounds of normal, port-scan, and
lateral-movement traffic FROM THE HOST IT IS RUN ON, targeting the other
allowed hosts. Run this once from each of hr, fin, and crit to get a
dataset where every host gets a turn being the "source", e.g.:

    hr   python3 /home/shuve/netshield-ai/generate_dataset.py
    fin  python3 /home/shuve/netshield-ai/generate_dataset.py
    crit python3 /home/shuve/netshield-ai/generate_dataset.py

(Guest is excluded as a source/destination since it's always blocked and
wouldn't produce useful "allowed traffic" samples.)
"""
import random
import socket
import subprocess
import sys
import time
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LABEL_FILE = os.path.join(BASE_DIR, "current_label.txt")
NORMAL_SCRIPT = os.path.join(BASE_DIR, "normal_traffic.py")
SCAN_SCRIPT = os.path.join(BASE_DIR, "scan_sim.py")
LATERAL_SCRIPT = os.path.join(BASE_DIR, "lateral_movement_sim.py")

ALL_HOSTS = {
    "hr": "10.0.0.1",
    "fin": "10.0.0.2",
    "crit": "10.0.0.3",
}

FLUSH_WAIT = 5
ROUNDS_PER_TYPE = 15


def get_my_ip():
    """Figure out which host we're running on by matching our hostname's
    IP against the known host IPs. Falls back to asking the user."""
    try:
        hostname = socket.gethostname()
        my_ip = socket.gethostbyname(hostname)
        if my_ip in ALL_HOSTS.values():
            return my_ip
    except Exception:
        pass
    # Fallback: check eth0-style interfaces for a known IP
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True)
        for ip in out.stdout.split():
            if ip in ALL_HOSTS.values():
                return ip
    except Exception:
        pass
    return None


def other_hosts(my_ip):
    return [ip for ip in ALL_HOSTS.values() if ip != my_ip]


def set_label(label):
    with open(LABEL_FILE, "w") as f:
        f.write(label + "\n")


def run_normal(i, my_ip):
    dst_ip = random.choice(other_hosts(my_ip))
    count = random.randint(6, 20)
    interval = round(random.uniform(0.5, 1.5), 2)
    print(f"[normal {i}] {my_ip} -> {dst_ip}  count={count} interval={interval}")
    set_label("normal")
    subprocess.run(["python3", NORMAL_SCRIPT, dst_ip, str(count), str(interval)])
    time.sleep(FLUSH_WAIT)


def run_scan(i, my_ip):
    dst_ip = random.choice(other_hosts(my_ip))
    start_port = random.randint(1, 50)
    span = random.randint(30, 150)
    end_port = start_port + span
    print(f"[scan {i}] {my_ip} -> {dst_ip}  ports {start_port}-{end_port}")
    set_label("attack")
    subprocess.run(["python3", SCAN_SCRIPT, dst_ip, str(start_port), str(end_port)])
    time.sleep(FLUSH_WAIT)


def run_lateral(i, my_ip):
    # Include Guest as a possible target even though it will be blocked --
    # the controller still records the contact attempt, which strengthens
    # the "touched multiple hosts" signal that marks lateral movement.
    lateral_targets = [ip for ip in ALL_HOSTS.values() if ip != my_ip] + ["10.0.0.4"]
    lateral_targets = list(dict.fromkeys(lateral_targets))  # dedupe, keep order
    n = random.randint(2, len(lateral_targets))
    dsts = random.sample(lateral_targets, n)
    print(f"[lateral {i}] {my_ip} -> {dsts}")
    set_label("lateral_movement")
    subprocess.run(["python3", LATERAL_SCRIPT] + dsts)
    time.sleep(FLUSH_WAIT)


def main():
    my_ip = get_my_ip()
    if my_ip is None:
        print("Could not determine this host's IP automatically.")
        my_ip = input("Enter this host's IP (e.g. 10.0.0.1): ").strip()
    if my_ip not in ALL_HOSTS.values():
        print(f"WARNING: {my_ip} is not in the known ALL_HOSTS list, continuing anyway.")

    print(f"Running as source host: {my_ip}")

    rounds = []
    for i in range(ROUNDS_PER_TYPE):
        rounds.append(("normal", i))
        rounds.append(("scan", i))
        rounds.append(("lateral", i))
    random.shuffle(rounds)

    total = len(rounds)
    for idx, (kind, i) in enumerate(rounds, 1):
        print(f"\n--- Round {idx}/{total} ({kind}) ---")
        if kind == "normal":
            run_normal(i, my_ip)
        elif kind == "scan":
            run_scan(i, my_ip)
        else:
            run_lateral(i, my_ip)

    print(f"\nDataset generation complete for source {my_ip}. Check flow_stats.csv.")


if __name__ == "__main__":
    main()
