#!/usr/bin/env python3
"""Who did each configuration actually contain, and why?
Reads results/decisions_<mode>.csv saved by experiment_runner.py."""
import csv, os, glob

BASE = os.path.dirname(os.path.abspath(__file__))
R = os.path.join(BASE, "results")
NAME = {"flat": "A Flat", "static": "B Static", "rule": "C Rule", "ml": "D ML"}

for mode in ["flat", "static", "rule", "ml"]:
    p = os.path.join(R, f"decisions_{mode}.csv")
    if not os.path.exists(p):
        continue
    rows = list(csv.DictReader(open(p)))
    acted = [r for r in rows if r["action"] in ("RESTRICT", "QUARANTINE")]
    quar = sorted({r["src_ip"] for r in rows if r["action"] == "QUARANTINE"})
    rest = sorted({(r["src_ip"], r["dst_ip"]) for r in rows
                   if r["action"] == "RESTRICT"})
    # what label drove enforcement, per src
    why = {}
    for r in acted:
        why.setdefault(r["src_ip"], set()).add(r["ml_prediction"])
    print(f"\n=== {NAME.get(mode, mode)} ===")
    print(f"  total decisions: {len(rows)} | enforced: {len(acted)}")
    print(f"  HOSTS QUARANTINED: {quar if quar else 'none'}")
    print(f"  PAIRS RESTRICTED:  {[f'{s}->{d}' for s,d in rest] if rest else 'none'}")
    for src, labs in sorted(why.items()):
        print(f"    {src} enforced on predictions: {sorted(labs)}")

print("\n--- KEY QUESTION: does ML quarantine FEWER hosts than rule? ---")
print("If ML quarantines only 10.0.0.1 (HR) but rule also hits .2/.3,")
print("that's ML's lower collateral -- the differentiator for your slide.")
