#!/usr/bin/env python3
"""Make clear_all() also rebuild the live reachability graph, so cleared
hosts return to normal (green) in the graph dashboard."""
import os, sys
F = os.path.join(os.path.dirname(os.path.abspath(__file__)), "simple_switch.py")
src = open(F).read()
if "rebuild live graph on clear" in src:
    sys.exit("Already patched.")

OLD = (
    "    def clear_all(self):\n"
    "        for src_ip in list(self.quarantined_hosts):\n"
    "            self.clear_quarantine(src_ip)\n"
    "        for pair in list(self.restricted_pairs):\n"
    "            self.clear_restrict(*pair)\n"
)
NEW = (
    "    def clear_all(self):\n"
    "        for src_ip in list(self.quarantined_hosts):\n"
    "            self.clear_quarantine(src_ip)\n"
    "        for pair in list(self.restricted_pairs):\n"
    "            self.clear_restrict(*pair)\n"
    "        # rebuild live graph on clear: all hosts reachable again\n"
    "        try:\n"
    "            self.live_graph = LiveReachabilityGraph(self.blocked_pairs)\n"
    "            print('*** CLEARED: live graph reset -- all hosts restored ***', flush=True)\n"
    "        except Exception:\n"
    "            pass\n"
)
if src.count(OLD) != 1:
    sys.exit(f"ABORT: matched {src.count(OLD)} (expected 1).")
src = src.replace(OLD, NEW)
open(F, "w").write(src)
print("Patched clear_all -- live graph resets on clear.")
