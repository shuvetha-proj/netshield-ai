#!/usr/bin/env python3
"""
Generates a self-contained HTML dashboard summarizing netshield-ai's
detection and response activity, reading from flow_stats.csv and
decisions_log.csv. Produces dashboard.html with embedded charts (no
internet connection needed to view it).
"""
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import base64
import io
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FLOW_CSV = os.path.join(BASE_DIR, "flow_stats.csv")
DECISIONS_CSV = os.path.join(BASE_DIR, "decisions_log.csv")
OUTPUT_HTML = os.path.join(BASE_DIR, "dashboard.html")

HOST_NAMES = {
    "10.0.0.1": "HR",
    "10.0.0.2": "Finance",
    "10.0.0.3": "Critical",
    "10.0.0.4": "Guest",
}


def fig_to_base64(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=110)
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


def chart_traffic_breakdown(flow_df):
    counts = flow_df["label"].value_counts()
    fig, ax = plt.subplots(figsize=(5, 4))
    colors = {"normal": "#4CAF50", "attack": "#FF9800", "lateral_movement": "#F44336"}
    bar_colors = [colors.get(l, "#999999") for l in counts.index]
    ax.bar(counts.index, counts.values, color=bar_colors)
    ax.set_title("Flow Counts by Traffic Type")
    ax.set_ylabel("Number of flows")
    for i, v in enumerate(counts.values):
        ax.text(i, v + 0.5, str(v), ha="center")
    plt.xticks(rotation=15)
    return fig_to_base64(fig)


def chart_decision_breakdown(dec_df):
    counts = dec_df["action"].value_counts()
    order = ["MONITOR", "RESTRICT", "QUARANTINE"]
    counts = counts.reindex(order).fillna(0)
    fig, ax = plt.subplots(figsize=(5, 4))
    colors = {"MONITOR": "#4CAF50", "RESTRICT": "#FF9800", "QUARANTINE": "#F44336"}
    ax.bar(counts.index, counts.values, color=[colors[a] for a in counts.index])
    ax.set_title("Controller Decisions")
    ax.set_ylabel("Number of decisions")
    for i, v in enumerate(counts.values):
        ax.text(i, v + 0.5, str(int(v)), ha="center")
    return fig_to_base64(fig)


def chart_risk_over_time(dec_df):
    fig, ax = plt.subplots(figsize=(8, 4))
    dec_df = dec_df.reset_index(drop=True)
    colors = {"MONITOR": "#4CAF50", "RESTRICT": "#FF9800", "QUARANTINE": "#F44336"}
    point_colors = [colors.get(a, "#999999") for a in dec_df["action"]]
    ax.scatter(dec_df.index, dec_df["risk_score"], c=point_colors, s=40)
    ax.axhline(0.3, color="gray", linestyle="--", linewidth=1, label="Restrict threshold")
    ax.axhline(0.7, color="black", linestyle="--", linewidth=1, label="Quarantine threshold")
    ax.set_title("Risk Score per Decision (in order observed)")
    ax.set_xlabel("Decision sequence")
    ax.set_ylabel("Risk score")
    ax.legend(loc="upper left", fontsize=8)
    return fig_to_base64(fig)


def chart_risk_by_destination(dec_df):
    dec_df = dec_df.copy()
    dec_df["dst_name"] = dec_df["dst_ip"].map(HOST_NAMES).fillna(dec_df["dst_ip"])
    grouped = dec_df.groupby("dst_name")["risk_score"].mean().sort_values(ascending=False)
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.bar(grouped.index, grouped.values, color="#2196F3")
    ax.set_title("Average Risk Score by Destination")
    ax.set_ylabel("Average risk score")
    for i, v in enumerate(grouped.values):
        ax.text(i, v + 0.01, f"{v:.2f}", ha="center")
    return fig_to_base64(fig)


def build_summary_stats(flow_df, dec_df):
    total_flows = len(flow_df)
    total_decisions = len(dec_df)
    quarantined = dec_df[dec_df["action"] == "QUARANTINE"]
    restricted = dec_df[dec_df["action"] == "RESTRICT"]

    quarantined_hosts = sorted(quarantined["src_ip"].unique())
    quarantined_hosts_named = [HOST_NAMES.get(h, h) for h in quarantined_hosts]

    stats = {
        "Total flows analyzed": total_flows,
        "Total ML decisions logged": total_decisions,
        "MONITOR decisions": len(dec_df[dec_df["action"] == "MONITOR"]),
        "RESTRICT decisions": len(restricted),
        "QUARANTINE decisions": len(quarantined),
        "Hosts quarantined": ", ".join(quarantined_hosts_named) if quarantined_hosts_named else "None",
        "Highest risk score observed": f"{dec_df['risk_score'].max():.2f}" if len(dec_df) else "N/A",
    }
    return stats


def build_decisions_table(dec_df, limit=30):
    df = dec_df.copy()
    df["src_name"] = df["src_ip"].map(HOST_NAMES).fillna(df["src_ip"])
    df["dst_name"] = df["dst_ip"].map(HOST_NAMES).fillna(df["dst_ip"])
    df = df[["timestamp", "src_name", "dst_name", "ml_prediction", "risk_score", "action"]]
    df = df.tail(limit)  # most recent decisions
    return df.to_html(index=False, classes="decisions-table", border=0)


def main():
    flow_df = pd.read_csv(FLOW_CSV)
    dec_df = pd.read_csv(DECISIONS_CSV)

    print(f"Loaded {len(flow_df)} flow records and {len(dec_df)} decisions.")

    traffic_chart = chart_traffic_breakdown(flow_df)
    decision_chart = chart_decision_breakdown(dec_df)
    risk_time_chart = chart_risk_over_time(dec_df)
    risk_dest_chart = chart_risk_by_destination(dec_df)

    stats = build_summary_stats(flow_df, dec_df)
    decisions_table_html = build_decisions_table(dec_df)

    stats_html = "".join(
        f"<div class='stat-card'><div class='stat-value'>{v}</div>"
        f"<div class='stat-label'>{k}</div></div>"
        for k, v in stats.items()
    )

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>netshield-ai Dashboard</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; background: #0f1117; color: #e0e0e0; margin: 0; padding: 24px; }}
  h1 {{ color: #ffffff; margin-bottom: 4px; }}
  .subtitle {{ color: #888; margin-top: 0; margin-bottom: 24px; }}
  .stats-row {{ display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 32px; }}
  .stat-card {{ background: #1c1f26; border-radius: 10px; padding: 16px 20px; min-width: 160px; flex: 1; }}
  .stat-value {{ font-size: 28px; font-weight: 700; color: #4CAF50; }}
  .stat-label {{ font-size: 13px; color: #aaa; margin-top: 4px; }}
  .charts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); gap: 24px; margin-bottom: 32px; }}
  .chart-card {{ background: #1c1f26; border-radius: 10px; padding: 16px; text-align: center; }}
  .chart-card img {{ max-width: 100%; border-radius: 6px; }}
  table.decisions-table {{ width: 100%; border-collapse: collapse; background: #1c1f26; border-radius: 10px; overflow: hidden; }}
  table.decisions-table th, table.decisions-table td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #333; font-size: 13px; }}
  table.decisions-table th {{ background: #2a2e38; color: #fff; }}
  section {{ margin-bottom: 36px; }}
  h2 {{ color: #fff; border-bottom: 2px solid #333; padding-bottom: 8px; }}
</style>
</head>
<body>
  <h1>netshield-ai: Detection &amp; Response Dashboard</h1>
  <p class="subtitle">ML-driven lateral-movement detection with adaptive SDN microsegmentation</p>

  <section>
    <h2>Summary</h2>
    <div class="stats-row">{stats_html}</div>
  </section>

  <section>
    <h2>Traffic &amp; Decisions</h2>
    <div class="charts-grid">
      <div class="chart-card"><img src="data:image/png;base64,{traffic_chart}"></div>
      <div class="chart-card"><img src="data:image/png;base64,{decision_chart}"></div>
      <div class="chart-card"><img src="data:image/png;base64,{risk_time_chart}"></div>
      <div class="chart-card"><img src="data:image/png;base64,{risk_dest_chart}"></div>
    </div>
  </section>

  <section>
    <h2>Recent Decisions (most recent {min(30, len(dec_df))})</h2>
    {decisions_table_html}
  </section>
</body>
</html>
"""

    with open(OUTPUT_HTML, "w") as f:
        f.write(html)

    print(f"Dashboard written to {OUTPUT_HTML}")
    print("Open it in a browser (e.g. via VS Code's file explorer, right-click > Open with Live Server, "
          "or just copy the path into Windows Explorer / your browser's address bar).")


if __name__ == "__main__":
    main()
