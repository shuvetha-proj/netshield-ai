#!/usr/bin/env python3
"""
Driver script: generates many varied rounds of normal, port-scan, and
lateral-movement traffic, setting current_label.txt before each round so
simple_switch.py logs flow_stats.csv rows with the correct label.

Run this from any host that can reach the others, e.g.:
    hr python3 /home/shuve/netshield-ai/generate_dataset.py
"""
import random
import subprocess
import time
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LABEL_FILE = os.path.join(BASE_DIR, "current_label.txt")
NORMAL_SCRIPT = os.path.join(BASE_DIR, "normal_traffic.py")
SCAN_SCRIPT = os.path.join(BASE_DIR, "scan_sim.py")
LATERAL_SCRIPT = os.path.join(BASE_DIR, "lateral_movement_sim.py")

# Allowed hosts (HR, Finance, Critical) -- Guest is excluded since it's
# always blocked and wouldn't produce useful "allowed traffic" samples.
ALLOWED_HOSTS = {
    "hr": "10.0.0.1",
    "fin": "10.0.0.2",
    "crit": "10.0.0.3",
}

FLUSH_WAIT = 5          # seconds to wait after each run for flows to flush
ROUNDS_PER_TYPE = 15     # how many of each traffic type to generate

def set_label(label):
    with open(LABEL_FILE, "w") as f:
        f.write(label + "\n")

def pick_src_and_dsts(min_dsts=1, max_dsts=1):
    """Pick a random source host and 1+ distinct destination hosts (not the source)."""
    src_name = random.choice(list(ALLOWED_HOSTS.keys()))
    others = [ip for name, ip in ALLOWED_HOSTS.items() if name != src_name]
    n = random.randint(min_dsts, min(max_dsts, len(others)))
    dsts = random.sample(others, n)
    return src_name, dsts

def run_normal(i):
    src_name, dsts = pick_src_and_dsts(1, 1)
    dst_ip = dsts[0]
    count = random.randint(6, 20)
    interval = round(random.uniform(0.5, 1.5), 2)
    print(f"[normal {i}] {src_name} -> {dst_ip}  count={count} interval={interval}")
    set_label("normal")
    subprocess.run(["python3", NORMAL_SCRIPT, dst_ip, str(count), str(interval)])
    time.sleep(FLUSH_WAIT)

def run_scan(i):
    src_name, dsts = pick_src_and_dsts(1, 1)
    dst_ip = dsts[0]
    start_port = random.randint(1, 50)
    span = random.randint(30, 150)
    end_port = start_port + span
    print(f"[scan {i}] {src_name} -> {dst_ip}  ports {start_port}-{end_port}")
    set_label("attack")
    subprocess.run(["python3", SCAN_SCRIPT, dst_ip, str(start_port), str(end_port)])
    time.sleep(FLUSH_WAIT)

def run_lateral(i):
    src_name, dsts = pick_src_and_dsts(2, 3)  # touch 2 or 3 distinct hosts
    print(f"[lateral {i}] {src_name} -> {dsts}")
    set_label("lateral_movement")
    subprocess.run(["python3", LATERAL_SCRIPT] + dsts)
    time.sleep(FLUSH_WAIT)

def main():
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
            run_normal(i)
        elif kind == "scan":
            run_scan(i)
        else:
            run_lateral(i)

    print("\nDataset generation complete. Check flow_stats.csv.")

if __name__ == "__main__":
    main()
