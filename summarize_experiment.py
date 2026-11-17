#!/usr/bin/env python3
"""Builds the 4-configuration comparison table + chart from results/exp_*.json.
Run after all four experiment runs are done."""
import glob, json, os

BASE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(BASE, "results")
ORDER = ["flat", "static", "rule", "ml"]
NAME = {"flat": "A: Flat", "static": "B: Static seg.",
        "rule": "C: Rule adaptive", "ml": "D: ML adaptive"}

rows = {}
for p in glob.glob(os.path.join(RESULTS, "exp_*.json")):
    d = json.load(open(p)); rows[d["mode"]] = d
present = [m for m in ORDER if m in rows]
if not present:
    raise SystemExit("No results/exp_*.json found -- run the experiments first.")

hdr = ["Configuration", "Guest reachable", "Protected reached (blast radius)",
       "Contained", "Time-to-contain (s)", "Legit traffic preserved"]
table = [hdr]
for m in present:
    d = rows[m]
    table.append([
        NAME[m],
        "yes" if d["guest_reachable_final"] else "no",
        f"{d['protected_reachable_final']}/2",
        "yes" if d["contained_crit"] else "no",
        str(d["time_to_contain_s"]) if d["time_to_contain_s"] is not None else "never",
        "yes" if d["legit_preserved"] else "NO (collateral!)",
    ])

widths = [max(len(r[i]) for r in table) for i in range(len(hdr))]
line = lambda r: " | ".join(c.ljust(widths[i]) for i, c in enumerate(r))
out = [line(table[0]), "-+-".join("-" * w for w in widths)] + [line(r) for r in table[1:]]
report = "\n".join(out)
print(report)
open(os.path.join(RESULTS, "configuration_comparison.txt"), "w").write(report + "\n")

# CSV
import csv
with open(os.path.join(RESULTS, "configuration_comparison.csv"), "w", newline="") as f:
    csv.writer(f).writerows(table)

# Chart
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    labels = [NAME[m] for m in present]
    blast = [rows[m]["protected_reachable_final"] for m in present]
    x = np.arange(len(present))
    fig, ax = plt.subplots(figsize=(7, 4.2))
    colors = ["#c0392b", "#e67e22", "#f1c40f", "#27ae60"][:len(present)]
    ax.bar(x, blast, color=colors)
    ax.set_xticks(x); ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.set_ylabel("Protected hosts attacker still reached")
    ax.set_ylim(0, 2.3); ax.set_title("Blast radius by configuration (lower = better)")
    for i, v in enumerate(blast):
        ax.text(i, v + 0.05, f"{v}/2", ha="center", fontweight="bold")
    ax.grid(axis="y", alpha=0.3); fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "configuration_comparison.png"), dpi=150)
    print(f"\nChart -> {RESULTS}/configuration_comparison.png")
except ImportError:
    print("\n[info] matplotlib missing -- table/CSV written, chart skipped")
print(f"Table -> {RESULTS}/configuration_comparison.txt, .csv")
