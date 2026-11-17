#!/usr/bin/env python3
"""
Driver script: generates many varied rounds of normal and attack traffic,
setting current_label.txt before each round so simple_switch.py logs
flow_stats.csv rows with the correct label. Run this from h1:
    h1 python3 /home/shuve/netshield-ai/generate_dataset.py
"""
import random
import subprocess
import time
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LABEL_FILE = os.path.join(BASE_DIR, "current_label.txt")
NORMAL_SCRIPT = os.path.join(BASE_DIR, "normal_traffic.py")
SCAN_SCRIPT = os.path.join(BASE_DIR, "scan_sim.py")

DST = "10.0.0.2"
FLUSH_WAIT = 5
ROUNDS_PER_TYPE = 10

def set_label(label):
    with open(LABEL_FILE, "w") as f:
        f.write(label + "\n")

def run_normal(i):
    count = random.randint(6, 20)
    interval = round(random.uniform(0.5, 1.5), 2)
    print(f"[{i}] NORMAL: count={count} interval={interval}")
    set_label("normal")
    subprocess.run(["python3", NORMAL_SCRIPT, DST, str(count), str(interval)])
    time.sleep(FLUSH_WAIT)

def run_attack(i):
    start_port = random.randint(1, 50)
    span = random.randint(30, 150)
    end_port = start_port + span
    print(f"[{i}] ATTACK: ports {start_port}-{end_port} (span={span})")
    set_label("attack")
    subprocess.run(["python3", SCAN_SCRIPT, DST, str(start_port), str(end_port)])
    time.sleep(FLUSH_WAIT)

def main():
    rounds = []
    for i in range(ROUNDS_PER_TYPE):
        rounds.append(("normal", i))
        rounds.append(("attack", i))
    random.shuffle(rounds)

    total = len(rounds)
    for idx, (kind, i) in enumerate(rounds, 1):
        print(f"\n--- Round {idx}/{total} ---")
        if kind == "normal":
            run_normal(i)
        else:
            run_attack(i)

    print("\nDataset generation complete. Check flow_stats.csv.")

if __name__ == "__main__":
    main()
