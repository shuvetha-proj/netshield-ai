#!/usr/bin/env python3
"""Add RESTRICT visualization (orange edges) to the graph dashboard."""
import os, sys
F = os.path.join(os.path.dirname(os.path.abspath(__file__)), "graph_dashboard.py")
src = open(F).read()
if "restedge" in src:
    sys.exit("Already patched.")

edits = []
# 1) CSS for restricted edges
edits.append((
    ".flowedge{stroke:var(--red);stroke-width:2.5;stroke-dasharray:6 4}",
    ".flowedge{stroke:var(--red);stroke-width:2.5;stroke-dasharray:6 4}\n"
    ".restedge{stroke:var(--orange);stroke-width:2.5;stroke-dasharray:3 3}",
))
# 2) draw restricted pairs as orange edges (before nodes)
edits.append((
    " // nodes (stay IN PLACE; red if attacker or quarantined)\n",
    " // restricted pairs: orange edges (one link blocked, not full quarantine)\n"
    " (d.restricted||[]).forEach(r=>{\n"
    "   const s=r.src,dd=r.dst;\n"
    "   if(POS[s]&&POS[dd]){svg.appendChild(el('line',{x1:POS[s][0],y1:POS[s][1],x2:POS[dd][0],y2:POS[dd][1],class:'restedge'}));}\n"
    " });\n"
    " // nodes (stay IN PLACE; red if attacker or quarantined)\n",
))
# 3) legend: add restricted link
edits.append((
    '      <span><span class="lg" style="background:var(--grey)"></span>guest (isolated)</span>\n'
    '    </div>',
    '      <span><span class="lg" style="background:var(--grey)"></span>guest (isolated)</span>\n'
    '      <span><span style="width:16px;border-top:2.5px dashed var(--orange);display:inline-block"></span>restricted link</span>\n'
    '    </div>',
))
for i,(old,new) in enumerate(edits,1):
    if src.count(old)!=1:
        sys.exit(f"ABORT edit {i}: matched {src.count(old)} (expected 1).")
    src = src.replace(old,new)
open(F,"w").write(src)
print("Patched -- restrict (orange edges) added to graph.")
