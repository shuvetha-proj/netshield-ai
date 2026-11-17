#!/usr/bin/env python3
"""
build_compare8.py -- Review 3 comparison page + tables + charts from the
RECORDED live runs in results/exp8/*.json (written by experiment8_runner.py).

Outputs (nothing else is touched; compare_live.html / decision_data.js stay as
the Review 2 fallback):
  compare8.html                         self-contained page, data inlined
  results/exp8/summary_exp8.csv         one row per config x scenario
  results/exp8/summary_exp8.txt         the same, as plain-text tables
  results/exp8/chart_lateral_critical.png
  results/exp8/chart_time_to_contain.png
  results/exp8/chart_benign_false.png

Every number on the page is computed from the JSON files. The panels replay
each run's logged decisions in their recorded order and timing.

Usage: python3 build_compare8.py
"""
import csv, glob, html, json, os, statistics as st
from collections import defaultdict

BASE = os.path.dirname(os.path.abspath(__file__))
IN = os.path.join(BASE, "results", "exp8")
PAGE = os.path.join(BASE, "compare8.html")

ORDER = ["flat", "static", "rule", "ml5", "ml2", "mlgc"]
NAME = {"flat": "A \u2014 Flat network", "static": "B \u2014 Static segmentation",
        "rule": "C \u2014 Rule-based adaptive", "ml5": "D \u2014 ML adaptive (5-factor)",
        "ml2": "D\u2032 \u2014 ML adaptive (2-factor)",
        "mlgc": "E \u2014 ML 5-factor + graph path cutting"}
SHORT = {"flat": "A Flat", "static": "B Static", "rule": "C Rule",
         "ml5": "D ML 5-factor", "ml2": "D\u2032 ML 2-factor", "mlgc": "E ML + path-cut"}
DESC = {"flat": "No segmentation, no response",
        "static": "Guest ACL only, no dynamic response",
        "rule": "Guest ACL + threshold rules, no ML",
        "ml5": "Guest ACL + Random Forest + 5-factor risk",
        "ml2": "Guest ACL + Random Forest + 2-factor risk",
        "mlgc": "As D, plus NetworkX path cutting toward critical assets"}
SCEN_ORDER = ["lateral", "scan", "benign"]
SCEN_NAME = {"lateral": "Lateral movement (HR \u2192 all 7 hosts)",
             "scan": "Port scan (IoT-2 \u2192 Database, ports 1\u2013150)",
             "benign": "Benign traffic (each host \u2192 its usual servers)"}
HOSTS = {"10.0.0.1": "HR", "10.0.0.2": "Finance", "10.0.0.3": "FileServer",
         "10.0.0.4": "Guest", "10.0.0.5": "Database", "10.0.0.6": "IoT-1",
         "10.0.0.7": "IoT-2", "10.0.0.8": "Admin"}
KEY_IP = {"hr": "10.0.0.1", "fin": "10.0.0.2", "fileserver": "10.0.0.3",
          "guest": "10.0.0.4", "database": "10.0.0.5", "iot1": "10.0.0.6",
          "iot2": "10.0.0.7", "admin": "10.0.0.8"}
CONTAIN = ("RESTRICT", "QUARANTINE")


# ---------------------------------------------------------------- load
def load():
    runs = defaultdict(list)
    for p in sorted(glob.glob(os.path.join(IN, "*.json"))):
        try:
            d = json.load(open(p))
        except (OSError, ValueError):
            print(f"[skip] unreadable {p}")
            continue
        if d.get("config") in ORDER and d.get("scenario") in SCEN_ORDER:
            runs[(d["config"], d["scenario"])].append(d)
    for k in runs:
        runs[k].sort(key=lambda d: d.get("run", 0))
    return runs


def misclassified(d):
    """Ground truth: attacker-originated flows are malicious, everything else
    (including victims' replies) is normal. Counts model/rule label errors."""
    att_ip = KEY_IP.get(d.get("attacker") or "", None)
    n = 0
    for r in d.get("rows", []):
        truth_mal = (att_ip is not None and r["src"] == att_ip)
        if r["pred"] == "path-cut":
            continue   # enforcement record, not a classifier label
        pred_mal = r["pred"] not in ("normal",)
        n += int(truth_mal != pred_mal)
    return n


# ---------------------------------------------------------------- aggregate
def mean(xs):
    xs = [x for x in xs if x is not None]
    return st.mean(xs) if xs else None


def sd(xs):
    xs = [x for x in xs if x is not None]
    return st.stdev(xs) if len(xs) > 1 else 0.0 if xs else None


def fmt(x, nd=1):
    return "\u2014" if x is None else f"{x:.{nd}f}"


def frac(bools):
    bools = list(bools)
    return f"{sum(bool(b) for b in bools)}/{len(bools)}"


def aggregate(runs):
    agg = {}
    for (cfg, sc), ds in runs.items():
        _m = [misclassified(d) for d in ds]; _f = [len(d.get("rows", [])) for d in ds]
        a = {"n": len(ds), "mis": mean(_m), "flows": mean(_f),
             "mis_pct": 100.0 * sum(_m) / max(1, sum(_f)),
             "collateral": sum(len(d.get("collateral_hosts", [])) for d in ds),
             "att_risk": mean([d.get("attacker_max_risk") for d in ds]),
             "oth_risk": mean([d.get("others_max_risk") for d in ds])}
        if sc == "lateral":
            a.update(hosts=mean([d["hosts_reached"] for d in ds]),
                     crit=mean([d["critical_reached"] for d in ds]),
                     crit_sd=sd([d["critical_reached"] for d in ds]),
                     contained=frac(d["contained"] for d in ds),
                     ttc=mean([d["time_to_contain_s"] for d in ds]),
                     ttc_sd=sd([d["time_to_contain_s"] for d in ds]),
                     ttc_n=sum(d["time_to_contain_s"] is not None for d in ds),
                     legit=frac(d["legit_preserved"] for d in ds))
        elif sc == "scan":
            a.update(blocked=frac(not d["target_reachable"] for d in ds),
                     other=frac(d["attacker_other_access"] for d in ds),
                     noncrit=(frac(d["attacker_noncritical_access"] for d in ds)
                              if all("attacker_noncritical_access" in d for d in ds) else "\u2014"),
                     ttc=mean([d["time_to_contain_s"] for d in ds]),
                     ttc_sd=sd([d["time_to_contain_s"] for d in ds]),
                     ttc_n=sum(d["time_to_contain_s"] is not None for d in ds),
                     legit=frac(d["legit_preserved"] for d in ds))
        else:
            fc = [d["false_containments"] for d in ds]
            a.update(fc_mean=mean(fc), fc_sd=sd(fc), fc_total=sum(fc),
                     quarantines=sum(sum(1 for r in d.get("rows", []) if r["action"] == "QUARANTINE") for d in ds),
                     pairs_ok=mean([sum(d["benign_pairs_ok"].values()) for d in ds]),
                     pairs_n=len(ds[0]["benign_pairs_ok"]),
                     max_risk=mean([d.get("max_risk") for d in ds]))
        agg[(cfg, sc)] = a
    return agg


def lab(a):
    return f"{fmt(a['mis'])} of {fmt(a['flows'])} ({a['mis_pct']:.0f}%)"


TABLES = {
    "lateral": (["Configuration", "Runs", "Hosts reached (of 7)", "Critical reached (of 2)",
                 "Contained", "Time to contain (s)", "Collateral hosts", "Legit traffic kept",
                 "Label errors / logged flows (per run)", "Attacker max risk", "Others max risk"],
                lambda a: [str(a["n"]), fmt(a["hosts"]), fmt(a["crit"]), a["contained"],
                           (fmt(a["ttc"]) + " \u00b1 " + fmt(a["ttc_sd"])) if a["ttc"] is not None else "never",
                           str(a["collateral"]), a["legit"], lab(a),
                           fmt(a["att_risk"], 3), fmt(a["oth_risk"], 3)]),
    "scan": (["Configuration", "Runs", "Target blocked", "Attacker keeps FileServer access",
              "Attacker keeps non-critical access (HR)",
              "Time to contain (s)", "Collateral hosts", "Legit traffic kept",
              "Label errors / logged flows (per run)", "Attacker max risk", "Others max risk"],
             lambda a: [str(a["n"]), a["blocked"], a["other"], a["noncrit"],
                        (fmt(a["ttc"]) + " \u00b1 " + fmt(a["ttc_sd"])) if a["ttc"] is not None else "never",
                        str(a["collateral"]), a["legit"], lab(a),
                        fmt(a["att_risk"], 3), fmt(a["oth_risk"], 3)]),
    "benign": (["Configuration", "Runs", "False containments / run", "False quarantines (total)",
                "Benign pairs working (of 6)", "Label errors / logged flows (per run)", "Max risk seen"],
               lambda a: [str(a["n"]), fmt(a["fc_mean"]) + " \u00b1 " + fmt(a["fc_sd"]),
                          str(a["quarantines"]), fmt(a["pairs_ok"]), lab(a),
                          fmt(a["max_risk"], 3)]),
}


def write_tables(agg):
    txt, rows_csv = [], []
    for sc in SCEN_ORDER:
        hdr, fn = TABLES[sc]
        body = [[SHORT[c]] + fn(agg[(c, sc)]) for c in ORDER if (c, sc) in agg]
        if not body:
            continue
        w = [max(len(r[i]) for r in [hdr] + body) for i in range(len(hdr))]
        line = lambda r: " | ".join(x.ljust(w[i]) for i, x in enumerate(r))
        txt += [SCEN_NAME[sc], line(hdr), "-+-".join("-" * x for x in w)] + [line(r) for r in body] + [""]
        rows_csv += [[sc] + hdr] + [[sc] + r for r in body] + [[]]
    open(os.path.join(IN, "summary_exp8.txt"), "w").write("\n".join(txt))
    with open(os.path.join(IN, "summary_exp8.csv"), "w", newline="") as f:
        csv.writer(f).writerows(rows_csv)
    print("\n".join(txt))


# ---------------------------------------------------------------- charts
def charts(agg):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[info] matplotlib missing -- charts skipped")
        return []
    BLUE, ORANGE = "#2a78d6", "#eb6834"          # categorical slots 1, 2
    INK, MUTED, GRID, SURF = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
    plt.rcParams.update({"font.size": 10, "axes.edgecolor": GRID, "axes.labelcolor": MUTED,
                         "xtick.color": MUTED, "ytick.color": MUTED, "text.color": INK,
                         "figure.facecolor": SURF, "axes.facecolor": SURF})

    def style(ax, title, ylabel):
        ax.set_title(title, loc="left", fontsize=12, fontweight="bold", color=INK, pad=12)
        ax.set_ylabel(ylabel)
        ax.grid(axis="y", color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.tick_params(length=0)

    made = []
    cfgs = [c for c in ORDER if (c, "lateral") in agg]
    if cfgs:
        fig, ax = plt.subplots(figsize=(7.2, 3.8))
        vals = [agg[(c, "lateral")]["crit"] for c in cfgs]
        errs = [agg[(c, "lateral")]["crit_sd"] for c in cfgs]
        bars = ax.bar([SHORT[c] for c in cfgs], vals, width=0.55, color=BLUE,
                      yerr=errs, error_kw={"ecolor": MUTED, "elinewidth": 1, "capsize": 3})
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.06, f"{v:.1f}/2", ha="center", color=INK, fontsize=9)
        ax.set_ylim(0, 2.4)
        style(ax, "Critical assets the attacker still reached (lateral movement, lower is better)",
              "Critical assets reached (of 2)")
        fig.text(0.01, 0.01, "Mean over runs; error bar = 1 SD. FileServer + Database.", color=MUTED, fontsize=8)
        fig.tight_layout(rect=(0, 0.03, 1, 1))
        p = os.path.join(IN, "chart_lateral_critical.png"); fig.savefig(p, dpi=160); plt.close(fig); made.append(p)

    cfgs = [c for c in ORDER if (c, "lateral") in agg or (c, "scan") in agg]
    if cfgs:
        import numpy as np
        fig, ax = plt.subplots(figsize=(7.2, 3.8))
        x = np.arange(len(cfgs)); w = 0.34
        for i, (sc, col, lab) in enumerate([("lateral", BLUE, "Lateral movement"), ("scan", ORANGE, "Port scan")]):
            vals = [(agg.get((c, sc)) or {}).get("ttc") for c in cfgs]
            errs = [(agg.get((c, sc)) or {}).get("ttc_sd") or 0 for c in cfgs]
            xs = x + (i - 0.5) * w
            ax.bar(xs, [v or 0 for v in vals], width=w - 0.03, color=col, label=lab,
                   yerr=[e if v is not None else 0 for v, e in zip(vals, errs)],
                   error_kw={"ecolor": MUTED, "elinewidth": 1, "capsize": 3})
            for xi, v in zip(xs, vals):
                if v is None:
                    ax.text(xi, 0.15, "never", ha="center", rotation=90, va="bottom", color=MUTED, fontsize=8)
        ax.set_xticks(x); ax.set_xticklabels([SHORT[c] for c in cfgs])
        ax.legend(frameon=False, loc="upper left")
        style(ax, "Time to containment (lower is better)", "Seconds from attack start")
        fig.text(0.01, 0.01, "Includes the 3 s flow-idle timeout; 1 s log resolution. \"never\" = no containment.",
                 color=MUTED, fontsize=8)
        fig.tight_layout(rect=(0, 0.03, 1, 1))
        p = os.path.join(IN, "chart_time_to_contain.png"); fig.savefig(p, dpi=160); plt.close(fig); made.append(p)

    cfgs = [c for c in ORDER if (c, "benign") in agg]
    if cfgs:
        fig, ax = plt.subplots(figsize=(7.2, 3.8))
        vals = [agg[(c, "benign")]["fc_mean"] for c in cfgs]
        bars = ax.bar([SHORT[c] for c in cfgs], vals, width=0.55, color=BLUE)
        top = max(vals + [1])
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + top * 0.03, f"{v:.1f}", ha="center", color=INK, fontsize=9)
        ax.set_ylim(0, top * 1.25)
        style(ax, "False containments on benign traffic (lower is better)", "Containments per run")
        fig.text(0.01, 0.01, "Any RESTRICT or QUARANTINE during benign-only traffic. A/B never respond by design.",
                 color=MUTED, fontsize=8)
        fig.tight_layout(rect=(0, 0.03, 1, 1))
        p = os.path.join(IN, "chart_benign_false.png"); fig.savefig(p, dpi=160); plt.close(fig); made.append(p)
    for p in made:
        print("chart ->", os.path.relpath(p, BASE))
    return made


# ---------------------------------------------------------------- narrative
def narrative(agg):
    out = []
    g = lambda c, s: agg.get((c, s))
    lat = {c: g(c, "lateral") for c in ORDER if g(c, "lateral")}
    if lat:
        uncont = [SHORT[c] for c, a in lat.items() if a["contained"].split("/")[0] == "0"]
        full = [SHORT[c] for c, a in lat.items() if a["contained"].split("/")[0] == a["contained"].split("/")[1]]
        s = "<b>Lateral movement:</b> "
        if uncont:
            s += f"{', '.join(uncont)} never contained the attacker. "
        if full:
            s += f"{', '.join(full)} contained it in every run"
            t = [f"{SHORT[c]} {fmt(lat[c]['ttc'])} s" for c in lat if SHORT[c] in full and lat[c]["ttc"] is not None]
            s += f" (mean time to containment: {'; '.join(t)})" if t else ""
            s += ". "
        col = [f"{SHORT[c]} {a['collateral']}" for c, a in lat.items() if a["collateral"]]
        s += ("Collateral containments: " + ", ".join(col) + ". ") if col else "No configuration contained an innocent host. "
        out.append(s)
    sc = {c: g(c, "scan") for c in ORDER if g(c, "scan")}
    if sc:
        s = "<b>Port scan:</b> target blocked \u2014 " + ", ".join(f"{SHORT[c]} {a['blocked']}" for c, a in sc.items())
        s += "; attacker kept its other access \u2014 " + ", ".join(f"{SHORT[c]} {a['other']}" for c, a in sc.items()) + "."
        out.append(s)
    bn = {c: g(c, "benign") for c in ORDER if g(c, "benign")}
    if bn:
        s = "<b>Benign traffic:</b> false containments per run \u2014 " + ", ".join(
            f"{SHORT[c]} {fmt(a['fc_mean'])}" for c, a in bn.items())
        q = sum(a["quarantines"] for a in bn.values())
        s += f". False quarantines across all benign runs: {q}."
        out.append(s)
    out.append("<b>Label errors</b> count prediction errors against ground truth (attacker flows malicious, "
               "everything else normal). Reply flows from victims are often labelled malicious; the directional "
               "and reply guards stop those labels from becoming containment.")
    return "<br>".join(out)


# ---------------------------------------------------------------- page
def build_page(runs, agg, made):
    data = {}
    for (cfg, sc), ds in runs.items():
        for d in ds:
            keep = {k: d.get(k) for k in ("run", "attacker", "target", "reach", "hosts_reached",
                                          "critical_reached", "contained", "target_reachable",
                                          "attacker_other_access", "time_to_contain_s",
                                          "collateral_hosts", "legit_preserved", "false_containments",
                                          "benign_pairs_ok", "attacker_max_risk", "others_max_risk")}
            keep["rows"] = d.get("rows", [])
            keep["mis"] = misclassified(d)
            data.setdefault(sc, {}).setdefault(cfg, []).append(keep)
    cfgs = [c for c in ORDER if any(c in data.get(s, {}) for s in data)]
    tables_html = []
    for sc in SCEN_ORDER:
        hdr, fn = TABLES[sc]
        body = [[NAME[c]] + fn(agg[(c, sc)]) for c in ORDER if (c, sc) in agg]
        if not body:
            continue
        th = "".join(f"<th>{html.escape(h)}</th>" for h in hdr)
        trs = "".join("<tr>" + "".join(f"<td>{html.escape(x)}</td>" for x in r) + "</tr>" for r in body)
        tables_html.append(f'<h3>{html.escape(SCEN_NAME[sc])}</h3><div class="tblwrap"><table class="agg">'
                           f"<thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table></div>")
    imgs = "".join(f'<img src="{os.path.relpath(p, BASE)}" alt="{os.path.basename(p)}">' for p in made)
    page = TEMPLATE
    for k, v in {"__DATA__": json.dumps(data), "__CFGS__": json.dumps(cfgs),
                 "__NAME__": json.dumps(NAME), "__DESC__": json.dumps(DESC),
                 "__SCEN__": json.dumps({s: SCEN_NAME[s] for s in SCEN_ORDER if s in data}),
                 "__HOSTS__": json.dumps(HOSTS), "__KEYIP__": json.dumps(KEY_IP),
                 "__TABLES__": "".join(tables_html), "__IMGS__": imgs,
                 "__NARR__": narrative(agg)}.items():
        page = page.replace(k, v)
    open(PAGE, "w").write(page)
    print("page ->", os.path.relpath(PAGE, BASE))


TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>netshield-ai — 8-host Configuration Comparison (recorded runs)</title>
<style>
:root{--bg:#0b0f14;--panel:#141b24;--panel2:#0f151d;--line:#232d3a;--txt:#e6edf3;--mut:#8b949e;
 --green:#3fb950;--red:#f85149;--orange:#e3a008;--grey:#3a434f;--edge:#2b3443;--warn:#f0b429}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:20px 18px 48px}
h1{font-size:23px;margin:0 0 3px} h3{font-size:14px;margin:22px 0 8px;color:var(--txt)}
.sub{color:var(--mut);margin:0 0 18px;font-size:13.5px}
.controls{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:18px}
button{font:inherit;font-weight:600;border:none;border-radius:9px;padding:10px 18px;cursor:pointer;color:#fff}
.btn-go{background:#da3633}.btn-go:hover{background:#f85149}.btn-go:disabled{opacity:.5;cursor:not-allowed}
.btn-reset{background:#2d3845}
select{font:inherit;font-weight:600;background:#1b232e;color:var(--txt);border:1px solid var(--line);border-radius:9px;padding:9px 12px}
.lbl{color:var(--mut);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(400px,1fr));gap:16px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px 14px 12px;position:relative}
.phead{display:flex;justify-content:space-between;align-items:baseline;gap:8px}
.pname{font-size:15px;font-weight:700}.pdesc{color:var(--mut);font-size:12px;margin:2px 0 6px}
.clock{position:absolute;top:14px;right:14px;font-size:11px;color:var(--mut);font-variant-numeric:tabular-nums}
.badge{font-size:12px;font-weight:700;padding:3px 10px;border-radius:20px;white-space:nowrap}
.badge.g{background:#17331d;color:var(--green)}.badge.o{background:#3a2c08;color:var(--orange)}.badge.r{background:#3a1715;color:var(--red)}
svg.net{width:100%;height:230px;display:block}
.node text{fill:var(--txt);font-size:11px;font-weight:600;text-anchor:middle;pointer-events:none}
.node .ip{fill:var(--mut);font-size:9px;font-weight:500}
.edge{stroke:var(--edge);stroke-width:2;fill:none;transition:stroke .3s,opacity .3s}
.ring{fill:none;stroke-width:2.5;opacity:0;transition:opacity .3s}.ring.on{opacity:1}
.statline{display:flex;gap:12px;flex-wrap:wrap;font-size:12.5px;margin:6px 0 8px;color:var(--mut)}
.statline b{color:var(--txt)}
.dtitle{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;display:flex;justify-content:space-between;margin:6px 0 2px}
.dwrap{max-height:210px;overflow-y:auto}
.dtbl{width:100%;border-collapse:collapse;font-size:11.5px}
.dtbl th{color:var(--mut);text-align:left;font-weight:600;padding:4px 6px;border-bottom:1px solid var(--line);font-size:10px;text-transform:uppercase;position:sticky;top:0;background:var(--panel)}
.dtbl td{padding:3px 6px;border-bottom:1px solid #1a222c;font-variant-numeric:tabular-nums}
.dtbl tr.mis td.pred{color:var(--warn)}
.act{font-weight:700}.act.MONITOR{color:var(--green)}.act.RESTRICT{color:var(--orange)}.act.QUARANTINE{color:var(--red)}
.legend{display:flex;gap:16px;margin:14px 2px 0;font-size:12px;color:var(--mut);flex-wrap:wrap}
.legend span{display:inline-flex;align-items:center;gap:6px}.dot{width:11px;height:11px;border-radius:50%;display:inline-block}
.box{margin-top:18px;background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:14px 16px;font-size:13.5px;line-height:1.75;color:var(--mut)}
.box b{color:var(--txt)}
.tblwrap{overflow-x:auto}
table.agg{border-collapse:collapse;font-size:12.5px;width:100%;min-width:760px}
table.agg th{color:var(--mut);text-align:left;font-weight:600;padding:6px 8px;border-bottom:1px solid var(--line);font-size:11px}
table.agg td{padding:6px 8px;border-bottom:1px solid #1a222c;font-variant-numeric:tabular-nums}
table.agg td:first-child{font-weight:600}
.imgs{display:grid;grid-template-columns:repeat(auto-fill,minmax(420px,1fr));gap:14px;margin-top:14px}
.imgs img{width:100%;border-radius:10px;border:1px solid var(--line)}
.tip{position:fixed;pointer-events:none;background:#1b232e;border:1px solid var(--line);border-radius:8px;padding:6px 9px;font-size:12px;opacity:0;transition:opacity .1s;z-index:9}
</style></head><body>
<h1>Ransomware Containment — Five Configurations, Recorded Runs (8-host VLAN topology)</h1>
<p class="sub">Each panel replays the decisions the controller actually logged during that configuration's run, in recorded order and timing. Final reachability comes from live ping checks at the end of the run. Nothing on this page is simulated.</p>
<div class="controls">
  <label class="lbl">Scenario <select id="scen"></select></label>
  <label class="lbl">Run <select id="run"></select></label>
  <label class="lbl">Speed <select id="speed"><option value="1">1×</option><option value="2" selected>2×</option><option value="4">4×</option></select></label>
  <button class="btn-go" id="go">▶ Replay</button>
  <button class="btn-reset" id="reset">↺ Reset</button>
</div>
<div class="grid" id="grid"></div>
<div class="legend">
  <span><span class="dot" style="background:var(--green)"></span>healthy / not reached</span>
  <span><span class="dot" style="background:var(--red)"></span>attacker / reached by attacker</span>
  <span><span class="dot" style="background:var(--orange)"></span>restricted link</span>
  <span><span class="dot" style="background:var(--grey)"></span>isolated by static ACL</span>
  <span><span style="width:14px;height:14px;border:2.5px solid var(--red);border-radius:50%;display:inline-block"></span>quarantined host</span>
  <span><span style="width:14px;height:14px;border:2.5px solid var(--orange);border-radius:50%;display:inline-block"></span>innocent host contained (collateral / false positive)</span>
  <span style="color:var(--warn)">⚠ label disagrees with ground truth</span>
</div>
<div class="box" id="narr">__NARR__</div>
<h3 style="margin-top:28px;font-size:17px">Aggregate results (all runs)</h3>
__TABLES__
<div class="imgs">__IMGS__</div>
<div class="tip" id="tip"></div>
<script>
const DATA=__DATA__, CFGS=__CFGS__, NAME=__NAME__, DESC=__DESC__, SCEN=__SCEN__, HOSTS=__HOSTS__, KEYIP=__KEYIP__;
const IPS=Object.keys(HOSTS), GUEST="10.0.0.4", CRIT=["10.0.0.3","10.0.0.5"];
const W=400,H=230,ns="http://www.w3.org/2000/svg";
const POS={}; IPS.forEach((ip,i)=>{const a=-Math.PI/2+i*2*Math.PI/IPS.length;POS[ip]=[W/2+150*Math.cos(a),H/2+88*Math.sin(a)];});
const BENIGN=[["hr","fileserver"],["fin","database"],["admin","fileserver"],["admin","database"],["iot1","admin"],["iot2","admin"]];
let timers=[];
const $=id=>document.getElementById(id);
function el(t,a){const e=document.createElementNS(ns,t);for(const k in a)e.setAttribute(k,a[k]);return e;}
function ek(a,b){return a<b?a+"|"+b:b+"|"+a;}
function cur(){return {sc:$("scen").value,run:+$("run").value};}
function rec(cfg){const {sc,run}=cur();const L=(DATA[sc]||{})[cfg]||[];return L.find(d=>d.run===run)||null;}
function edgesFor(sc,d){
  if(sc==="benign") return BENIGN.map(p=>[KEYIP[p[0]],KEYIP[p[1]]]);
  if(!d||!d.attacker) return [];
  const a=KEYIP[d.attacker];
  if(sc==="scan") return [[a,KEYIP[d.target]],[a,"10.0.0.3"]];
  return IPS.filter(ip=>ip!==a).map(ip=>[a,ip]);
}
function buildPanel(cfg){
  const p=document.createElement("div");p.className="panel";p.id="p-"+cfg;
  p.innerHTML='<div class="clock" id="clk-'+cfg+'"></div>'+
   '<div class="phead"><span class="pname">'+NAME[cfg]+'</span><span class="badge" id="bdg-'+cfg+'" style="visibility:hidden"></span></div>'+
   '<div class="pdesc">'+DESC[cfg]+'</div>'+
   '<svg class="net" viewBox="0 0 '+W+' '+H+'" id="svg-'+cfg+'"></svg>'+
   '<div class="statline" id="st-'+cfg+'"></div>'+
   '<div class="dtitle"><span>Logged decisions</span><span id="q-'+cfg+'"></span></div>'+
   '<div class="dwrap"><table class="dtbl"><thead><tr><th>t (s)</th><th>Source</th><th>Dest</th><th>Prediction</th><th>Risk</th><th>Action</th></tr></thead><tbody id="tb-'+cfg+'"></tbody></table></div>';
  $("grid").appendChild(p);
}
function draw(cfg){
  const {sc}=cur(),d=rec(cfg),svg=$("svg-"+cfg);svg.innerHTML="";
  const acl=cfg!=="flat";
  edgesFor(sc,d).forEach(([a,b])=>{
    const e=el("line",{x1:POS[a][0],y1:POS[a][1],x2:POS[b][0],y2:POS[b][1],class:"edge",id:"e-"+cfg+"-"+ek(a,b)});
    if(acl&&(a===GUEST||b===GUEST))e.setAttribute("opacity","0.25");
    svg.appendChild(e);
  });
  IPS.forEach(ip=>{
    const [x,y]=POS[ip],g=el("g",{class:"node"});
    g.appendChild(el("circle",{cx:x,cy:y,r:23,class:"ring",id:"r-"+cfg+"-"+ip}));
    const c=el("circle",{cx:x,cy:y,r:17,id:"n-"+cfg+"-"+ip,fill:(ip===GUEST&&acl)?"var(--grey)":"var(--green)"});
    if(CRIT.includes(ip)){c.setAttribute("stroke","#f0b429");c.setAttribute("stroke-width","2");}
    g.appendChild(c);
    const t=el("text",{x:x,y:y+1});t.textContent=HOSTS[ip];g.appendChild(t);
    const t2=el("text",{x:x,y:y+30,class:"ip"});t2.textContent=ip;g.appendChild(t2);
    svg.appendChild(g);
  });
  if(d&&d.attacker&&sc!=="benign") $("n-"+cfg+"-"+KEYIP[d.attacker]).setAttribute("fill","var(--red)");
  $("tb-"+cfg).innerHTML=d?"":'<tr><td colspan="6" style="color:var(--mut)">No recorded run for this configuration.</td></tr>';
  $("st-"+cfg).innerHTML="";$("q-"+cfg).textContent="";$("clk-"+cfg).textContent="";
  $("bdg-"+cfg).style.visibility="hidden";
}
function edge(cfg,a,b){return $("e-"+cfg+"-"+ek(a,b));}
function applyRow(cfg,r,att){
  const tr=document.createElement("tr");
  const truthMal=att&&r.src===att, predMal=r.pred!=="normal", mis=r.pred!=="path-cut"&&truthMal!==predMal;
  if(mis)tr.className="mis";
  tr.innerHTML="<td>"+r.dt.toFixed(1)+"</td><td>"+HOSTS[r.src]+"</td><td>"+HOSTS[r.dst]+'</td><td class="pred">'+r.pred+(mis?" ⚠":"")+"</td><td>"+(+r.risk).toFixed(3)+'</td><td class="act '+r.action+'">'+r.action+"</td>";
  $("tb-"+cfg).appendChild(tr);
  const e=edge(cfg,r.src,r.dst);
  if(e&&e.getAttribute("stroke")!=="var(--orange)"&&!e.dataset.cut){e.setAttribute("stroke","#cfd8dc");setTimeout(()=>{if(!e.dataset.cut&&e.getAttribute("stroke")==="#cfd8dc")e.removeAttribute("stroke");},350);}
  const innocent=!att||r.src!==att;
  if(r.action==="RESTRICT"){
    if(e){e.setAttribute("stroke","var(--orange)");e.setAttribute("stroke-dasharray","6 4");e.dataset.cut=1;}
    if(innocent){const g=$("r-"+cfg+"-"+r.src);g.setAttribute("stroke","var(--orange)");g.classList.add("on");}
  }
  if(r.action==="QUARANTINE"){
    const g=$("r-"+cfg+"-"+r.src);g.setAttribute("stroke",innocent?"var(--orange)":"var(--red)");g.classList.add("on");
    IPS.forEach(ip=>{const x=edge(cfg,r.src,ip);if(x&&x.getAttribute("stroke")!=="var(--orange)"){x.setAttribute("stroke","var(--red)");x.setAttribute("stroke-dasharray","2 6");x.setAttribute("opacity","0.55");x.dataset.cut=1;}});
  }
}
function finish(cfg,d,sc){
  const st=$("st-"+cfg),b=$("bdg-"+cfg);b.style.visibility="visible";
  const yes=v=>'<b style="color:var(--green)">'+v+'</b>', no=v=>'<b style="color:var(--red)">'+v+'</b>';
  const ttc=d.time_to_contain_s==null?"never":d.time_to_contain_s+" s";
  if(sc==="lateral"){
    Object.entries(d.reach||{}).forEach(([k,v])=>{if(v)$("n-"+cfg+"-"+KEYIP[k]).setAttribute("fill","var(--red)");});
    st.innerHTML="Hosts reached: <b>"+d.hosts_reached+"/7</b> · Critical: <b>"+d.critical_reached+"/2</b> · Contained: "+(d.contained?yes("yes"):no("no"))+" · Time to contain: <b>"+ttc+"</b> · Collateral: <b>"+(d.collateral_hosts.length?d.collateral_hosts.map(i=>HOSTS[i]).join(", "):"none")+"</b>";
    b.className="badge "+(d.contained?"g":"r");b.textContent=d.contained?"contained · "+d.critical_reached+"/2":d.critical_reached+"/2 critical reached";
  } else if(sc==="scan"){
    const tgt=KEYIP[d.target];
    if(d.target_reachable)$("n-"+cfg+"-"+tgt).setAttribute("fill","var(--red)");
    st.innerHTML="Target blocked: "+(d.target_reachable?no("no"):yes("yes"))+" · Attacker keeps other access: <b>"+(d.attacker_other_access?"yes":"no")+"</b> · Time to contain: <b>"+ttc+"</b> · Collateral: <b>"+(d.collateral_hosts.length?d.collateral_hosts.map(i=>HOSTS[i]).join(", "):"none")+"</b>";
    b.className="badge "+(d.target_reachable?"r":(d.attacker_other_access?"g":"o"));
    b.textContent=d.target_reachable?"target reached":(d.attacker_other_access?"link restricted only":"host cut off");
  } else {
    const ok=Object.values(d.benign_pairs_ok||{}).filter(Boolean).length,n=Object.keys(d.benign_pairs_ok||{}).length;
    Object.entries(d.benign_pairs_ok||{}).forEach(([k,v])=>{const [a,c]=k.split("->");const e=edge(cfg,KEYIP[a],KEYIP[c]);if(e&&v&&!e.dataset.cut)e.setAttribute("stroke","var(--green)");});
    st.innerHTML="False containments: <b>"+d.false_containments+"</b> · Benign pairs working: <b>"+ok+"/"+n+"</b>";
    b.className="badge "+(d.false_containments?"o":"g");b.textContent=d.false_containments?d.false_containments+" false containment(s)":"no false positives";
  }
  const q=$("q-"+cfg);q.textContent=d.mis+" of "+d.rows.length+" flows mislabelled";q.style.color=d.mis?"var(--warn)":"var(--green)";
}
function clear(){timers.forEach(clearTimeout);timers=[];CFGS.forEach(draw);$("go").disabled=false;}
function play(){
  clear();$("go").disabled=true;
  const {sc}=cur(),sp=+$("speed").value;let longest=0;
  CFGS.forEach(cfg=>{
    const d=rec(cfg);if(!d)return;
    const att=d.attacker&&sc!=="benign"?KEYIP[d.attacker]:null;
    const rows=[...d.rows].sort((a,b)=>a.dt-b.dt);
    const end=(rows.length?rows[rows.length-1].dt:0)+1;longest=Math.max(longest,end);
    rows.forEach(r=>timers.push(setTimeout(()=>{applyRow(cfg,r,att);$("clk-"+cfg).textContent="t = "+r.dt.toFixed(1)+" s";},r.dt*1000/sp)));
    timers.push(setTimeout(()=>{finish(cfg,d,sc);$("clk-"+cfg).textContent="run "+d.run+" · complete";},end*1000/sp));
  });
  timers.push(setTimeout(()=>{$("go").disabled=false;},longest*1000/sp+50));
}
function fillRuns(){
  const sc=$("scen").value;let mx=0;
  Object.values(DATA[sc]||{}).forEach(L=>L.forEach(d=>mx=Math.max(mx,d.run)));
  $("run").innerHTML="";for(let i=1;i<=mx;i++)$("run").innerHTML+='<option value="'+i+'">'+i+"</option>";
}
Object.entries(SCEN).forEach(([k,v])=>$("scen").innerHTML+='<option value="'+k+'">'+v+"</option>");
CFGS.forEach(buildPanel);fillRuns();clear();
$("scen").onchange=()=>{fillRuns();clear();};$("run").onchange=clear;
$("go").onclick=play;$("reset").onclick=clear;
// hover: show host name + ip on nodes
document.addEventListener("mousemove",ev=>{const t=$("tip");const c=ev.target;
  if(c.tagName==="circle"&&c.id.startsWith("n-")){const ip=c.id.split("-").slice(2).join("-");t.textContent=HOSTS[ip]+" · "+ip+(CRIT.includes(ip)?" · critical asset":"")+(ip===GUEST?" · Guest VLAN (ACL)":"");t.style.left=ev.clientX+12+"px";t.style.top=ev.clientY+12+"px";t.style.opacity=1;}
  else t.style.opacity=0;});
</script></body></html>
"""


def main():
    runs = load()
    if not runs:
        raise SystemExit(f"No results found in {IN} -- run experiment8_runner.py first.")
    print("found:", ", ".join(f"{c}/{s}x{len(v)}" for (c, s), v in sorted(runs.items())))
    agg = aggregate(runs)
    write_tables(agg)
    made = charts(agg)
    build_page(runs, agg, made)


if __name__ == "__main__":
    main()
