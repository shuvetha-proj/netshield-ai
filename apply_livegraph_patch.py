#!/usr/bin/env python3
"""Wire the live reachability graph into simple_switch.py:
 - always: update the graph on quarantine/restrict and report path status
 - GRAPH_CUT=on: also cut the specific edge on the attacker's path to a
   critical asset (graph-informed targeted cut).
Asserts anchors match exactly once."""
import os, sys

F = os.path.join(os.path.dirname(os.path.abspath(__file__)), "simple_switch.py")
src = open(F).read()
if "LiveReachabilityGraph" in src:
    sys.exit("Already patched -- no changes made.")

edits = []

# 1) import + read GRAPH_CUT env var
edits.append((
    "from risk_engine_v2 import compute_risk_v2\n"
    "RISK_MODEL = os.environ.get('RISK_MODEL', '2factor').lower()",
    "from risk_engine_v2 import compute_risk_v2\n"
    "from live_graph import LiveReachabilityGraph\n"
    "RISK_MODEL = os.environ.get('RISK_MODEL', '2factor').lower()\n"
    "GRAPH_CUT = os.environ.get('GRAPH_CUT', 'off').lower() == 'on'",
))

# 2) build the live graph after blocked_pairs is finalised (after the guest loop)
edits.append((
    "        self.blocked_pairs = set()\n"
    "        for _o in _others:\n"
    "            self.blocked_pairs.add((GUEST, _o))\n"
    "            self.blocked_pairs.add((_o, GUEST))\n",
    "        self.blocked_pairs = set()\n"
    "        for _o in _others:\n"
    "            self.blocked_pairs.add((GUEST, _o))\n"
    "            self.blocked_pairs.add((_o, GUEST))\n"
    "        # live reachability graph (Review 3 -- path analysis + cutting)\n"
    "        self.live_graph = LiveReachabilityGraph(self.blocked_pairs)\n",
))

# 3) announce GRAPH_CUT after RISK_MODEL print
edits.append((
    "        print(f'*** RISK_MODEL = {RISK_MODEL} ***', flush=True)\n",
    "        print(f'*** RISK_MODEL = {RISK_MODEL} ***', flush=True)\n"
    "        print(f'*** GRAPH_CUT = {\"on\" if GRAPH_CUT else \"off\"} ***', flush=True)\n",
))

# 4) after enforcement actions, update the graph and report path status.
#    Hook into the QUARANTINE / RESTRICT enforcement calls.
edits.append((
    "                if action == \"QUARANTINE\":\n"
    "                    self.enforce_quarantine(rec.src_ip)\n"
    "                elif action == \"RESTRICT\":\n"
    "                    self.enforce_restrict(rec.src_ip, rec.dst_ip)\n",
    "                if action == \"QUARANTINE\":\n"
    "                    self.enforce_quarantine(rec.src_ip)\n"
    "                    self.live_graph.cut_host(rec.src_ip)\n"
    "                    print(\"    \" + self.live_graph.report(rec.src_ip), flush=True)\n"
    "                elif action == \"RESTRICT\":\n"
    "                    self.enforce_restrict(rec.src_ip, rec.dst_ip)\n"
    "                    self.live_graph.cut_pair(rec.src_ip, rec.dst_ip)\n"
    "                    # GRAPH_CUT: if the attacker still has a path to a\n"
    "                    # critical asset, cut the next edge on that path too.\n"
    "                    if GRAPH_CUT:\n"
    "                        _asset, _path = self.live_graph.path_to_critical(rec.src_ip)\n"
    "                        if _path and len(_path) >= 2:\n"
    "                            _a, _b = _path[0], _path[1]\n"
    "                            self.enforce_restrict(_a, _b)\n"
    "                            self.live_graph.cut_pair(_a, _b)\n"
    "                            print(f\"    [graph-cut] severing path edge \"\n"
    "                                  f\"{_a} -> {_b} toward critical asset\", flush=True)\n"
    "                    print(\"    \" + self.live_graph.report(rec.src_ip), flush=True)\n",
))

for i, (old, new) in enumerate(edits, 1):
    n = src.count(old)
    if n != 1:
        sys.exit(f"ABORT: edit {i} matched {n} times (expected 1). No change.")
    src = src.replace(old, new)

open(F, "w").write(src)
print("Patched simple_switch.py -- live graph + graph-cut wired in.")
