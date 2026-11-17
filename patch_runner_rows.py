F = "experiment8_runner.py"
s = open(F).read()
ROWS = '[{"dt": round(r["t"] - t0, 1), **{k: r[k] for k in ("src", "dst", "pred", "risk", "action")}} for r in rows]'
a_old = '        "collateral_hosts": sorted({r["src"] for r in others if r["action"] in CONTAIN}),\n'
b_old = '            "decisions": len(rows)}\n'
assert s.count(a_old) == 1, "analyse() anchor not found"
assert s.count(b_old) == 1, "run_benign() anchor not found"
s = s.replace(a_old, a_old + f'        "rows": {ROWS},\n')
s = s.replace(b_old, '            "decisions": len(rows),\n' + f'            "rows": {ROWS}}}\n')
open(F, "w").write(s)
print("runner now saves decision rows per run")
