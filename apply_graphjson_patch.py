#!/usr/bin/env python3
import os, sys
F = os.path.join(os.path.dirname(os.path.abspath(__file__)), "simple_switch.py")
src = open(F).read()
if "GRAPH_STATE_FILE" in src:
    sys.exit("Already patched -- no changes made.")

edits = []
# 1) define the graph-state file path next to LIVE_STATE_FILE
edits.append((
    'LIVE_STATE_FILE = os.path.join(BASE_DIR, "live_state.json")',
    'LIVE_STATE_FILE = os.path.join(BASE_DIR, "live_state.json")\n'
    'GRAPH_STATE_FILE = os.path.join(BASE_DIR, "graph_state.json")',
))
# 2) write graph_state.json inside the live_state writer loop (after live_state dump)
edits.append((
    "                with open(LIVE_STATE_FILE, \"w\") as f:\n"
    "                    json.dump(state, f)\n",
    "                with open(LIVE_STATE_FILE, \"w\") as f:\n"
    "                    json.dump(state, f)\n"
    "                # --- live reachability graph snapshot (Review 3) ---\n"
    "                try:\n"
    "                    from live_graph import NAME as _GNAME, CRITICAL_ASSETS as _GCRIT, ALL_HOSTS as _GALL\n"
    "                    _VLAN = {\"10.0.0.1\":10,\"10.0.0.2\":20,\"10.0.0.3\":30,\n"
    "                             \"10.0.0.4\":40,\"10.0.0.5\":30,\"10.0.0.6\":50,\n"
    "                             \"10.0.0.7\":50,\"10.0.0.8\":60}\n"
    "                    _edges = [[s, d] for (s, d) in self.live_graph.G.edges()]\n"
    "                    _quar = sorted(self.live_graph.quarantined)\n"
    "                    # path status for any quarantined/active attacker\n"
    "                    _attackers = _quar or [p['src'] for p in state['restricted_pairs']]\n"
    "                    _paths = {}\n"
    "                    for _atk in set(_attackers):\n"
    "                        _a, _p = self.live_graph.path_to_critical(_atk)\n"
    "                        _paths[_atk] = ([_GNAME.get(h,h) for h in _p] if _p else None)\n"
    "                    gstate = {\n"
    "                        \"timestamp\": state[\"timestamp\"],\n"
    "                        \"hosts\": [{\"ip\": h, \"name\": _GNAME.get(h,h),\n"
    "                                   \"vlan\": _VLAN.get(h,0),\n"
    "                                   \"critical\": h in _GCRIT,\n"
    "                                   \"quarantined\": h in _quar} for h in _GALL],\n"
    "                        \"edges\": _edges,\n"
    "                        \"quarantined\": _quar,\n"
    "                        \"paths\": _paths,\n"
    "                    }\n"
    "                    with open(GRAPH_STATE_FILE, \"w\") as gf:\n"
    "                        json.dump(gstate, gf)\n"
    "                except Exception as _ge:\n"
    "                    pass\n",
))
for i,(old,new) in enumerate(edits,1):
    if src.count(old)!=1:
        sys.exit(f"ABORT edit {i}: matched {src.count(old)} (expected 1).")
    src = src.replace(old,new)
open(F,"w").write(src)
print("Patched -- graph_state.json writer added.")
