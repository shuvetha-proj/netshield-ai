#!/usr/bin/env python3
"""Side-by-side: live 2-factor risk_engine vs enhanced 5-term risk_engine_v2,
on the same flows. Standalone/offline. Output -> results/risk_engine_comparison.png + .txt"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from risk_engine import compute_risk              # live 2-factor (0-1)
from risk_engine_v2 import compute_risk_v2, LABEL_PROB

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
os.makedirs(OUT, exist_ok=True)

# same flows, described by (label, dst, fanout, pps)
FLOWS = [
    ("Normal -> Finance",      "normal",           "10.0.0.2", 1, 1.3),
    ("Lateral -> HR",          "lateral_movement", "10.0.0.1", 3, 12.0),
    ("Lateral -> Finance",     "lateral_movement", "10.0.0.2", 3, 12.0),
    ("Lateral -> Server",      "lateral_movement", "10.0.0.3", 3, 12.0),
    ("Scan -> HR",             "attack",           "10.0.0.1", 1, 15.0),
]

rows = []
for name, label, dst, fan, pps in FLOWS:
    # 2-factor (live): scale 0-1 -> 0-100 for comparison
    r1, a1, _ = compute_risk(label, dst)
    s1 = round(r1 * 100, 1)
    # 5-term (enhanced)
    s2, a2, _ = compute_risk_v2(LABEL_PROB[label], dst,
                                distinct_dst_hosts_recent=fan, packets_per_sec=pps)
    rows.append((name, s1, a1, s2, a2))

# text report
rep = ["RISK ENGINE COMPARISON  (2-factor live  vs  5-term enhanced)",
       "", f"{'Flow':20s} {'2-factor':>9s} {'action':11s} {'5-term':>7s} {'action':11s}"]
for name, s1, a1, s2, a2 in rows:
    flag = "  <- escalated" if (a1 != a2 and s2 > s1) else ""
    rep.append(f"{name:20s} {s1:9.1f} {a1:11s} {s2:7.1f} {a2:11s}{flag}")
rep += ["",
        "The 5-term model adds connection-rate and fan-out behaviour to the",
        "ML-label x criticality baseline, so it escalates on attacker BEHAVIOUR,",
        "not destination value alone -- containing the compromised host earlier."]
report = "\n".join(rep)
open(os.path.join(OUT, "risk_engine_comparison.txt"), "w").write(report + "\n")
print(report)

# chart
names = [r[0] for r in rows]
s1v = [r[1] for r in rows]; s2v = [r[3] for r in rows]
x = np.arange(len(names)); w = 0.38
fig, ax = plt.subplots(figsize=(10, 5))
ax.bar(x - w/2, s1v, w, label="2-factor (live)", color="#6b7280")
ax.bar(x + w/2, s2v, w, label="5-term (enhanced)", color="#2f81f7")
ax.axhline(70, color="#e5484d", ls="--", lw=1, label="QUARANTINE threshold")
ax.axhline(30, color="#f5a524", ls="--", lw=1, label="RESTRICT threshold")
ax.set_xticks(x); ax.set_xticklabels(names, rotation=20, ha="right", fontsize=9)
ax.set_ylabel("Risk score (0-100)"); ax.set_ylim(0, 100)
ax.set_title("Risk scoring: 2-factor baseline vs 5-term weighted model")
ax.legend(fontsize=8); ax.grid(axis="y", alpha=0.3)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "risk_engine_comparison.png"), dpi=150)
print(f"\nChart -> {OUT}/risk_engine_comparison.png")
