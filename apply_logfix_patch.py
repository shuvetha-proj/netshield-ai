#!/usr/bin/env python3
"""Log the ENFORCED action, not the pre-guard intent, so decisions_log.csv
matches live reachability. Moves log_decision() to after the directional guard.
Backs up first; asserts the edit matches exactly once."""
import os, shutil, sys

F = os.path.join(os.path.dirname(os.path.abspath(__file__)), "simple_switch.py")
src = open(F).read()
if "# log AFTER directional guard" in src:
    sys.exit("Already patched -- no changes made.")

# Find the current block: log_decision is called, THEN flat/static forces
# MONITOR, THEN the directional guard runs. We remove the early log_decision
# and re-insert it after the guard, just before enforcement.

OLD = (
    "                self.log_decision(rec.src_ip, rec.dst_ip, prediction, risk, action)\n"
    "                print(f\"[{self.mode}] DECISION: {rec.src_ip} -> {rec.dst_ip}  {explanation}\",\n"
    "                      flush=True)\n"
)
NEW = (
    "                print(f\"[{self.mode}] DETECTED: {rec.src_ip} -> {rec.dst_ip}  {explanation}\",\n"
    "                      flush=True)\n"
)

if src.count(OLD) != 1:
    sys.exit(f"ABORT: detection-log anchor matched {src.count(OLD)} times (expected 1).")
src = src.replace(OLD, NEW)

# Now insert the log_decision call right before enforcement, using the FINAL
# (post-guard) action -- after the directional guard has possibly set MONITOR.
OLD2 = (
    "                if action == \"QUARANTINE\":\n"
    "                    self.enforce_quarantine(rec.src_ip)\n"
    "                elif action == \"RESTRICT\":\n"
    "                    self.enforce_restrict(rec.src_ip, rec.dst_ip)\n"
    "                # MONITOR: no enforcement action needed."
)
NEW2 = (
    "                # log AFTER directional guard: record the action actually\n"
    "                # ENFORCED, so decisions_log.csv matches live reachability.\n"
    "                self.log_decision(rec.src_ip, rec.dst_ip, prediction, risk, action)\n"
    "                if action == \"QUARANTINE\":\n"
    "                    self.enforce_quarantine(rec.src_ip)\n"
    "                elif action == \"RESTRICT\":\n"
    "                    self.enforce_restrict(rec.src_ip, rec.dst_ip)\n"
    "                # MONITOR: no enforcement action needed."
)

if src.count(OLD2) != 1:
    sys.exit(f"ABORT: enforcement anchor matched {src.count(OLD2)} times (expected 1).")
src = src.replace(OLD2, NEW2)

shutil.copy(F, F.replace("simple_switch.py", "simple_switch_before_logfix.py"))
open(F, "w").write(src)
print("Patched. Backup -> simple_switch_before_logfix.py")
