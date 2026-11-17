"""Adds config 'mlgc' (ML 5-factor + GRAPH_CUT=on) to the experiment.
Patches 3 files, each backed up first, each edit asserted to match exactly once.
  simple_switch.py      : log every path-cut restriction to decisions_log.csv
  experiment8_runner.py : accept 'mlgc'; scan also checks attacker -> HR access
  build_compare8.py     : show 'mlgc' + the non-critical-access column
"""
import shutil, sys

def U(t):  # same text with \\uXXXX escapes written as real characters
    return t.replace("\\u2032", "\u2032").replace("\\u2014", "\u2014")

def patch(path, edits, bak):
    s = open(path).read()
    chosen = []
    for old, new, n in edits:
        for o, nw in ((old, new), (U(old), U(new))):
            if s.count(o) == n:
                chosen.append((o, nw)); break
        else:
            sys.exit(f"ABORT {path}: expected {n} match(es) for {old[:60]!r}. Nothing written.")
    shutil.copy2(path, bak)
    for o, nw in chosen:
        s = s.replace(o, nw)
    open(path, "w").write(s)
    print(f"patched {path}  (backup: {bak})")

# ---- 1. controller: log path-cut restrictions so they are measured ----------
S = "simple_switch.py"
src = open(S).read().split("\n")
hits = [i for i, l in enumerate(src) if l.strip() == "self.live_graph.cut_pair(_a, _b)"]
if len(hits) != 1:
    sys.exit(f"ABORT {S}: path-cut anchor found {len(hits)} times. Nothing written.")
if any("path-cut" in l for l in src):
    sys.exit(f"ABORT {S}: already patched.")
i = hits[0]; ind = src[i][: len(src[i]) - len(src[i].lstrip())]
shutil.copy2(S, "simple_switch_before_graphcutlog.py")
src[i + 1:i + 1] = [ind + 'self.log_decision(_a, _b, "path-cut", risk, "RESTRICT")']
open(S, "w").write("\n".join(src))
print(f"patched {S}  (backup: simple_switch_before_graphcutlog.py)")

# ---- 2. runner -------------------------------------------------------------
patch("experiment8_runner.py", [
    ('CONFIGS = ("flat", "static", "rule", "ml5", "ml2")',
     'CONFIGS = ("flat", "static", "rule", "ml5", "ml2", "mlgc")', 1),
    ('  ml2    : NETSHIELD_MODE=ml RISK_MODEL=2factor python3 run_controller.py\n',
     '  ml2    : NETSHIELD_MODE=ml RISK_MODEL=2factor python3 run_controller.py\n'
     '  mlgc   : NETSHIELD_MODE=ml RISK_MODEL=5factor GRAPH_CUT=on python3 run_controller.py\n', 1),
    ('           "attacker_other_access": ping(h[att], HOSTS["fileserver"]),\n',
     '           "attacker_other_access": ping(h[att], HOSTS["fileserver"]),\n'
     '           "attacker_noncritical_access": ping(h[att], HOSTS["hr"]),\n', 1),
], "experiment8_runner_before_mlgc.py")

# ---- 3. builder ------------------------------------------------------------
patch("build_compare8.py", [
    ('ORDER = ["flat", "static", "rule", "ml5", "ml2"]',
     'ORDER = ["flat", "static", "rule", "ml5", "ml2", "mlgc"]', 1),
    ('        "ml2": "D\\u2032 \\u2014 ML adaptive (2-factor)"}',
     '        "ml2": "D\\u2032 \\u2014 ML adaptive (2-factor)",\n'
     '        "mlgc": "E \\u2014 ML 5-factor + graph path cutting"}', 1),
    ('         "ml5": "D ML 5-factor", "ml2": "D\\u2032 ML 2-factor"}',
     '         "ml5": "D ML 5-factor", "ml2": "D\\u2032 ML 2-factor", "mlgc": "E ML + path-cut"}', 1),
    ('        "ml2": "Guest ACL + Random Forest + 2-factor risk"}',
     '        "ml2": "Guest ACL + Random Forest + 2-factor risk",\n'
     '        "mlgc": "As D, plus NetworkX path cutting toward critical assets"}', 1),
    ('        pred_mal = r["pred"] not in ("normal",)\n',
     '        if r["pred"] == "path-cut":\n            continue   # enforcement record, not a classifier label\n'
     '        pred_mal = r["pred"] not in ("normal",)\n', 1),
    ('                     other=frac(d["attacker_other_access"] for d in ds),\n',
     '                     other=frac(d["attacker_other_access"] for d in ds),\n'
     '                     noncrit=(frac(d["attacker_noncritical_access"] for d in ds)\n'
     '                              if all("attacker_noncritical_access" in d for d in ds) else "\\u2014"),\n', 1),
    ('"Configuration", "Runs", "Target blocked", "Attacker keeps other access",',
     '"Configuration", "Runs", "Target blocked", "Attacker keeps FileServer access",\n'
     '              "Attacker keeps non-critical access (HR)",', 1),
    ('             lambda a: [str(a["n"]), a["blocked"], a["other"],',
     '             lambda a: [str(a["n"]), a["blocked"], a["other"], a["noncrit"],', 1),
    ('predMal=r.pred!=="normal", mis=truthMal!==predMal;',
     'predMal=r.pred!=="normal", mis=r.pred!=="path-cut"&&truthMal!==predMal;', 1),
], "build_compare8_before_mlgc.py")
print("done -- now compile-check all three files")
