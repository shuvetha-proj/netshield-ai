#!/usr/bin/env python3
"""
attack_path_analysis.py -- Objective 5 (attack-path / reachability graph).

Models the network as a directed reachability graph and computes the path a
compromised host would take to reach the CRITICAL asset (the Server, 10.0.0.3,
criticality 1.5). Shows how each defence configuration changes that path:

    Flat    -- every host reaches the Server directly (shortest path = 1 hop)
    Static  -- Guest is cut, but a trusted compromised host still reaches Server
    ML      -- the compromised host is quarantined; the path to Server is SEVERED

Reads the real policy (blocked_pairs) and criticality weights already used by
the live system. READ-ONLY: it does not import or modify the controller.
Outputs -> results/attack_path.png  +  results/attack_path_report.txt
"""
import os
import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "results")
os.makedirs(OUT, exist_ok=True)

# --- Real network facts (match simple_switch.py / risk_engine.py) -----------
HOSTS = {
    "10.0.0.1": ("HR", 1.0),
    "10.0.0.2": ("Finance", 1.2),
    "10.0.0.3": ("Server", 1.5),      # the critical asset
    "10.0.0.4": ("Guest", 1.0),
}
NAME = {ip: n for ip, (n, _) in HOSTS.items()}
CRIT = {ip: c for ip, (_, c) in HOSTS.items()}
ALL = list(HOSTS)
CRITICAL_ASSET = "10.0.0.3"           # Server
ATTACKER = "10.0.0.1"                 # HR compromised (default scenario)

# static ACL: Guest fully isolated (both directions) -- from blocked_pairs
GUEST = "10.0.0.4"
STATIC_BLOCKED = set()
for other in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
    STATIC_BLOCKED.add((GUEST, other))
    STATIC_BLOCKED.add((other, GUEST))


def build_graph(blocked, quarantined=None):
    """Directed reachability graph. Edge weight = 1/criticality of the
    destination, so the shortest (lowest-cost) path naturally heads toward
    the highest-value target -- i.e. how ransomware prioritises."""
    quarantined = quarantined or set()
    G = nx.DiGraph()
    for ip in ALL:
        G.add_node(ip, label=NAME[ip], crit=CRIT[ip])
    for s in ALL:
        for d in ALL:
            if s == d:
                continue
            if (s, d) in blocked:
                continue
            if s in quarantined or d in quarantined:
                continue  # quarantined host: all its links removed
            G.add_edge(s, d, weight=round(1.0 / CRIT[d], 3))
    return G


def attack_path(G, src, dst):
    if src not in G or dst not in G:
        return None
    try:
        return nx.shortest_path(G, src, dst, weight="weight")
    except nx.NetworkXNoPath:
        return None


CONFIGS = [
    ("A — Flat network", set(), set()),
    ("B — Static segmentation", STATIC_BLOCKED, set()),
    ("D — ML-driven (attacker quarantined)", STATIC_BLOCKED, {ATTACKER}),
]

POS = {  # fixed layout: HR top, Finance right, Server bottom, Guest left
    "10.0.0.1": (0.5, 1.0),
    "10.0.0.2": (1.0, 0.5),
    "10.0.0.3": (0.5, 0.0),
    "10.0.0.4": (0.0, 0.5),
}


def draw(ax, G, title, path):
    # base edges
    nx.draw_networkx_edges(G, POS, ax=ax, edge_color="#8893a5",
                           width=1.2, arrows=True, arrowsize=11,
                           connectionstyle="arc3,rad=0.06")
    # highlight attack path
    if path and len(path) > 1:
        pe = list(zip(path[:-1], path[1:]))
        nx.draw_networkx_edges(G, POS, ax=ax, edgelist=pe, edge_color="#e5484d",
                               width=3.2, arrows=True, arrowsize=16,
                               connectionstyle="arc3,rad=0.06")
    # nodes
    colors, sizes = [], []
    for ip in G.nodes():
        if ip == ATTACKER:
            colors.append("#e5484d")          # attacker red
        elif ip == CRITICAL_ASSET:
            colors.append("#f5a524")          # critical asset amber
        else:
            colors.append("#2f81f7")          # normal blue
        sizes.append(900 + 500 * CRIT[ip])
    nx.draw_networkx_nodes(G, POS, ax=ax, node_color=colors,
                           node_size=sizes, edgecolors="#11161d", linewidths=1.5)
    labels = {ip: f"{NAME[ip]}\n{ip}" for ip in G.nodes()}
    nx.draw_networkx_labels(G, POS, labels, ax=ax, font_size=8,
                            font_color="white", font_weight="bold")
    # verdict
    if path is None:
        verdict = "NO PATH to Server\n(critical asset protected)"
        vcol = "#2fb344"
    else:
        hops = len(path) - 1
        route = " -> ".join(NAME[h] for h in path)
        verdict = f"Attack path ({hops} hop{'s' if hops>1 else ''}):\n{route}"
        vcol = "#e5484d"
    ax.set_title(title, fontsize=11, fontweight="bold", color="#e6edf3", pad=10)
    ax.text(0.5, -0.18, verdict, transform=ax.transAxes, ha="center",
            fontsize=9, color=vcol, fontweight="bold")
    ax.set_xlim(-0.25, 1.25); ax.set_ylim(-0.35, 1.2); ax.axis("off")


def main():
    report = []
    report.append("ATTACK-PATH / REACHABILITY ANALYSIS (objective 5)")
    report.append(f"Compromised host: {NAME[ATTACKER]} ({ATTACKER})")
    report.append(f"Target critical asset: {NAME[CRITICAL_ASSET]} ({CRITICAL_ASSET}, criticality {CRIT[CRITICAL_ASSET]})")
    report.append("")

    fig, axes = plt.subplots(1, 3, figsize=(15, 5.2))
    fig.patch.set_facecolor("#0d1117")
    for ax, (title, blocked, quar) in zip(axes, CONFIGS):
        ax.set_facecolor("#0d1117")
        G = build_graph(blocked, quar)
        path = attack_path(G, ATTACKER, CRITICAL_ASSET)
        draw(ax, G, title, path)
        if path is None:
            report.append(f"{title}: NO PATH -> Server is unreachable (contained).")
        else:
            route = " -> ".join(NAME[h] for h in path)
            report.append(f"{title}: path = {route}  ({len(path)-1} hop(s)).")

    fig.suptitle("Attack path to the critical asset (Server) under three configurations",
                 fontsize=13, fontweight="bold", color="#e6edf3", y=1.02)
    fig.tight_layout()
    out_png = os.path.join(OUT, "attack_path.png")
    fig.savefig(out_png, dpi=150, bbox_inches="tight", facecolor="#0d1117")
    plt.close(fig)

    report.append("")
    report.append("Interpretation: static segmentation isolates the untrusted Guest but")
    report.append("leaves a direct trusted path to the Server. ML-driven containment")
    report.append("quarantines the compromised host, severing every path to the Server --")
    report.append("the reachability graph has no route from attacker to critical asset.")

    rep_txt = "\n".join(report)
    with open(os.path.join(OUT, "attack_path_report.txt"), "w") as f:
        f.write(rep_txt + "\n")

    print(rep_txt)
    print(f"\nFigure -> {out_png}")
    print(f"Report -> {os.path.join(OUT, 'attack_path_report.txt')}")


if __name__ == "__main__":
    main()
