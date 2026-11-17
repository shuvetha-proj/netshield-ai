#!/usr/bin/env python3
"""Surgically add a 4-configuration mode switch to simple_switch.py.
Backs up the original and asserts every edit matches exactly once."""
import os, shutil, sys

F = os.path.join(os.path.dirname(os.path.abspath(__file__)), "simple_switch.py")
src = open(F).read()
if "NETSHIELD_MODE" in src:
    sys.exit("Already patched (NETSHIELD_MODE present) -- no changes made.")

EDITS = []

# 1) import rule_decide next to compute_risk
EDITS.append((
    "from risk_engine import compute_risk",
    "from risk_engine import compute_risk\nfrom rule_baseline import rule_decide",
))

# 2) mode switch, right after the blocked_pairs set is defined
EDITS.append((
    "            ('10.0.0.4', '10.0.0.3'), ('10.0.0.3', '10.0.0.4'),  # guest <-> crit\n        }\n",
    "            ('10.0.0.4', '10.0.0.3'), ('10.0.0.3', '10.0.0.4'),  # guest <-> crit\n        }\n"
    "\n"
    "        # --- Experiment configuration switch (objective 7) ----------\n"
    "        # NETSHIELD_MODE picks which of the 4 evaluated configs runs:\n"
    "        #   flat   (A) no segmentation, no response\n"
    "        #   static (B) Guest ACL only, no dynamic response\n"
    "        #   rule   (C) Guest ACL + threshold-rule response (no ML)\n"
    "        #   ml     (D) Guest ACL + ML-driven response        [default]\n"
    "        _mode_file = os.path.join(BASE_DIR, 'mode.txt')\n"
    "        _experiment = ('NETSHIELD_MODE' in os.environ) or os.path.exists(_mode_file)\n"
    "        self.mode = (os.environ.get('NETSHIELD_MODE')\n"
    "                     or (open(_mode_file).read().strip()\n"
    "                         if os.path.exists(_mode_file) else 'ml')).lower()\n"
    "        print(f'*** NETSHIELD_MODE = {self.mode}  (experiment={_experiment}) ***',\n"
    "              flush=True)\n"
    "        if self.mode == 'flat':\n"
    "            self.blocked_pairs = set()   # config A: no static ACL at all\n"
    "        # Experiment runs log flows to a per-mode scratch file so the\n"
    "        # training dataset (flow_stats.csv) is never contaminated.\n"
    "        self.flow_log_file = (\n"
    "            os.path.join(BASE_DIR, f'flow_stats_exp_{self.mode}.csv')\n"
    "            if _experiment else FLOW_LOG_FILE)\n"
    "        # ------------------------------------------------------------\n",
))

# 3a) flow-log header init -> use self.flow_log_file
EDITS.append((
    "        if not os.path.exists(FLOW_LOG_FILE):\n"
    "            with open(FLOW_LOG_FILE, \"w\", newline=\"\") as f:",
    "        if not os.path.exists(self.flow_log_file):\n"
    "            with open(self.flow_log_file, \"w\", newline=\"\") as f:",
))

# 3b) flow append in flush -> use self.flow_log_file
EDITS.append((
    "            with open(FLOW_LOG_FILE, \"a\", newline=\"\") as f:",
    "            with open(self.flow_log_file, \"a\", newline=\"\") as f:",
))

# 4) detector + enforcement branch by mode
EDITS.append((
    "                features = rec.to_ml_features(dist_hosts)\n"
    "                X = pd.DataFrame([features], columns=ML_FEATURES)\n"
    "                prediction = self.model.predict(X)[0]\n"
    "                risk, action, explanation = compute_risk(prediction, rec.dst_ip)\n"
    "                self.log_decision(rec.src_ip, rec.dst_ip, prediction, risk, action)\n"
    "                print(f\"ML DECISION: {rec.src_ip} -> {rec.dst_ip}  {explanation}\",\n"
    "                      flush=True)\n"
    "\n"
    "                # NEW: actually enforce the decision.\n"
    "                if action == \"QUARANTINE\":\n"
    "                    self.enforce_quarantine(rec.src_ip)\n"
    "                elif action == \"RESTRICT\":\n"
    "                    self.enforce_restrict(rec.src_ip, rec.dst_ip)\n"
    "                # MONITOR: no enforcement action needed.",

    "                features = rec.to_ml_features(dist_hosts)\n"
    "                if self.mode == \"rule\":\n"
    "                    # Config C: fixed-threshold detector, NO ML model.\n"
    "                    prediction, risk, action, explanation = rule_decide(\n"
    "                        dist_hosts, len(rec.dst_ports), rec.dst_ip)\n"
    "                else:\n"
    "                    X = pd.DataFrame([features], columns=ML_FEATURES)\n"
    "                    prediction = self.model.predict(X)[0]\n"
    "                    risk, action, explanation = compute_risk(prediction, rec.dst_ip)\n"
    "                self.log_decision(rec.src_ip, rec.dst_ip, prediction, risk, action)\n"
    "                print(f\"[{self.mode}] DECISION: {rec.src_ip} -> {rec.dst_ip}  {explanation}\",\n"
    "                      flush=True)\n"
    "\n"
    "                # Configs A (flat) and B (static) do NO dynamic response:\n"
    "                # detection may run, but containment is disabled so the\n"
    "                # blast radius can be measured with no adaptive defence.\n"
    "                if self.mode in (\"flat\", \"static\"):\n"
    "                    action = \"MONITOR\"\n"
    "\n"
    "                if action == \"QUARANTINE\":\n"
    "                    self.enforce_quarantine(rec.src_ip)\n"
    "                elif action == \"RESTRICT\":\n"
    "                    self.enforce_restrict(rec.src_ip, rec.dst_ip)\n"
    "                # MONITOR: no enforcement action needed.",
))

for i, (old, new) in enumerate(EDITS, 1):
    n = src.count(old)
    if n != 1:
        sys.exit(f"ABORT: edit {i} matched {n} times (expected 1). "
                 f"No file written.")
    src = src.replace(old, new)

shutil.copy(F, F.replace("simple_switch.py", "simple_switch_before_modes.py"))
open(F, "w").write(src)
print("Patched. Backup -> simple_switch_before_modes.py")
