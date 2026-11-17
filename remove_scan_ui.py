F = "graph_dashboard.py"
lines = open(F).read().split("\n")
hr = [i for i, l in enumerate(lines) if l.strip() == '<hr style="border:none;border-top:1px solid #2a2e38;margin:16px 0;">']
end = [i for i, l in enumerate(lines) if "One source probing one target" in l]
assert len(hr) == 1, f"hr matches: {len(hr)}"
assert len(end) == 1, f"hint matches: {len(end)}"
assert 0 < end[0] - hr[0] < 25, "unexpected block size"
del lines[hr[0]:end[0] + 1]
open(F, "w").write("\n".join(lines))
print(f"removed lines {hr[0]+1}-{end[0]+1}")
