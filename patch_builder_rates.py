F = "build_compare8.py"
s = open(F).read()
edits = [
 ('        a = {"n": len(ds), "mis": mean([misclassified(d) for d in ds]),\n',
  '        _m = [misclassified(d) for d in ds]; _f = [len(d.get("rows", [])) for d in ds]\n'
  '        a = {"n": len(ds), "mis": mean(_m), "flows": mean(_f),\n'
  '             "mis_pct": 100.0 * sum(_m) / max(1, sum(_f)),\n', 1),
 ('"Misclassified flows / run"', '"Label errors / logged flows (per run)"', 3),
 ('fmt(a["mis"])', 'lab(a)', 3),
 ('TABLES = {\n', 'def lab(a):\n    return f"{fmt(a[\'mis\'])} of {fmt(a[\'flows\'])} ({a[\'mis_pct\']:.0f}%)"\n\n\nTABLES = {\n', 1),
 ('q.textContent=d.mis+" misclassified";', 'q.textContent=d.mis+" of "+d.rows.length+" flows mislabelled";', 1),
 ('"<b>Misclassified flows</b> count label errors', '"<b>Label errors</b> count prediction errors', 1),
]
for old, new, n in edits:
    assert s.count(old) == n, f"expected {n} of {old[:50]!r}, found {s.count(old)}"
    s = s.replace(old, new)
open(F, "w").write(s)
print("builder patched: label errors now shown as count of logged flows + %")
