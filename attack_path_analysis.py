#!/usr/bin/env python3
"""
attack_path_analysis.py -- Objective 5 (attack-path / reachability graph).
Shows the attacker's route to the critical Server under ALL FOUR configurations:
  Flat    -- no segmentation; direct path to Server
  Static  -- Guest cut, but trusted path to Server remains
  Rule    -- rule-based adaptive: HR quarantined -> path severed
  ML      -- ML-driven adaptive: HR quarantined -> path severed
READ-ONLY. Output -> results/attack_path.png + results/attack_path_report.txt
"""
import os
import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "results"); os.makedirs(OUT, exist_ok=True)

HOSTS = {"10.0.0.1": ("HR", 1.0), "10.0.0.2": ("Finance", 1.2),
         "10.0.0.3": ("Server", 1.5), "10.0.0.4": ("Guest", 1.0)}
NAME = {ip: n for ip, (n, _) in HOSTS.items()}
CRIT = {ip: c for ip, (_, c) in HOSTS.items()}
ALL = list(HOSTS)
CRITICAL_ASSET = "10.0.0.3"
ATTACKER = "10.0.0.1"
GUEST = "10.0.0.4"

STATIC_BLOCKED = set()
for other in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
    STATIC_BLOCKED.add((GUEST, other)); STATIC_BLOCKED.add((other, GUEST))


def build_graph(blocked, quarantined=None):
    quarantined = quarantined or set()
    G = nx.DiGraph()
    for ip in ALL:
        G.add_node(ip, label=NAME[ip], crit=CRIT[ip])
    for s in ALL:
        for d in ALL:
            if s == d or (s, d) in blocked:
                continue
            if s in quarantined or d in quarantined:
                continue
            G.add_edge(s, d, weight=round(1.0 / CRIT[d], 3))
    return G


def attack_path(G, src, dst):
    if src not in G or dst not in G:
        return None
    try:
        return nx.shortest_path(G, src, dst, weight="weight")
    except nx.NetworkXNoPath:
        return None


# Config: (title, blocked set, quarantined set)
# For the HR attacker: Rule and ML both quarantine HR -> path severed.
CONFIGS = [
    ("A - Flat network", set(), set()),
    ("B - Static segmentation", STATIC_BLOCKED, set()),
    ("C - Rule-based (HR quarantined)", STATIC_BLOCKED, {ATTACKER}),
    ("D - ML-driven (HR quarantined)", STATIC_BLOCKED, {ATTACKER}),
]

POS = {"10.0.0.1": (0.5, 1.0), "10.0.0.2": (1.0, 0.5),
       "10.0.0.3": (0.5, 0.0), "10.0.0.4": (0.0, 0.5)}


def draw(ax, G, title, path):
    nx.draw_networkx_edges(G, POS, ax=ax, edge_color="#8893a5", width=1.2,
                           arrows=True, arrowsize=10, connectionstyle="arc3,rad=0.06")
    if path and len(path) > 1:
        pe = list(zip(path[:-1], path[1:]))
        nx.draw_networkx_edges(G, POS, ax=ax, edgelist=pe, edge_color="#e5484d",
                               width=3.0, arrows=True, arrowsize=15, connectionstyle="arc3,rad=0.06")
    colors, sizes = [], []
    for ip in G.nodes():
        colors.append("#e5484d" if ip == ATTACKER else ("#f5a524" if ip == CRITICAL_ASSET else "#2f81f7"))
        sizes.append(700 + 400 * CRIT[ip])
    nx.draw_networkx_nodes(G, POS, ax=ax, node_color=colors, node_size=sizes,
                           edgecolors="#11161d", linewidths=1.5)
    nx.draw_networkx_labels(G, POS, {ip: NAME[ip] for ip in G.nodes()}, ax=ax,
                            font_size=8, font_color="white", font_weight="bold")
    if path is None:
        verdict, vcol = "NO PATH to Server\n(contained)", "#2fb344"
    else:
        hops = len(path) - 1
        verdict = f"Path ({hops} hop{'s' if hops>1 else ''}):\n" + " -> ".join(NAME[h] for h in path)
        vcol = "#e5484d"
    ax.set_title(title, fontsize=10, fontweight="bold", color="#e6edf3", pad=8)
    ax.text(0.5, -0.22, verdict, transform=ax.transAxes, ha="center",
            fontsize=8.5, color=vcol, fontweight="bold")
    ax.set_xlim(-0.25, 1.25); ax.set_ylim(-0.4, 1.2); ax.axis("off")


def main():
    report = ["ATTACK-PATH / REACHABILITY ANALYSIS (objective 5)",
              f"Compromised host: {NAME[ATTACKER]} ({ATTACKER})",
              f"Target: {NAME[CRITICAL_ASSET]} ({CRITICAL_ASSET}, criticality {CRIT[CRITICAL_ASSET]})", ""]
    fig, axes = plt.subplots(1, 4, figsize=(18, 4.8))
    fig.patch.set_facecolor("#0d1117")
    for ax, (title, blocked, quar) in zip(axes, CONFIGS):
        ax.set_facecolor("#0d1117")
        G = build_graph(blocked, quar)
        path = attack_path(G, ATTACKER, CRITICAL_ASSET)
        draw(ax, G, title, path)
        report.append(f"{title}: " + ("NO PATH -> Server unreachable (contained)."
                      if path is None else "path = " + " -> ".join(NAME[h] for h in path) + f" ({len(path)-1} hop(s))."))
    fig.suptitle("Attack path to the critical asset (Server) under four configurations",
                 fontsize=13, fontweight="bold", color="#e6edf3", y=1.03)
    fig.tight_layout()
    out = os.path.join(OUT, "attack_path.png")
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="#0d1117")
    plt.close(fig)
    report += ["", "Flat & Static leave a direct trusted path to the Server.",
               "Rule-based and ML-driven both quarantine the compromised host,",
               "severing every path to the Server (no route from attacker to critical asset)."]
    open(os.path.join(OUT, "attack_path_report.txt"), "w").write("\n".join(report) + "\n")
    print("\n".join(report))
    print(f"\nFigure -> {out}")


if __name__ == "__main__":
    main()
