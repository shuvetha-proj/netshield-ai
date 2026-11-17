#!/usr/bin/env python3
"""Add a selectable 5-factor risk model to simple_switch.py.
RISK_MODEL=5factor uses risk_engine_v2 with real conn-rate + failed-ratio;
default (2factor) keeps the proven engine. Asserts anchors match once."""
import os, sys

F = os.path.join(os.path.dirname(os.path.abspath(__file__)), "simple_switch.py")
src = open(F).read()
if "RISK_MODEL" in src:
    sys.exit("Already patched -- no changes made.")

edits = []

# 1) import the 5-factor engine + read the RISK_MODEL env var (after conn tracker import)
edits.append((
    "from connection_tracker import ConnectionTracker",
    "from connection_tracker import ConnectionTracker\n"
    "from risk_engine_v2 import compute_risk_v2\n"
    "RISK_MODEL = os.environ.get('RISK_MODEL', '2factor').lower()",
))

# 2) announce which risk model after the mode print
edits.append((
    "        print(f'*** NETSHIELD_MODE = {self.mode}  (experiment={_experiment}) ***',\n"
    "              flush=True)\n",
    "        print(f'*** NETSHIELD_MODE = {self.mode}  (experiment={_experiment}) ***',\n"
    "              flush=True)\n"
    "        print(f'*** RISK_MODEL = {RISK_MODEL} ***', flush=True)\n",
))

# 3) the decision block: add a 5-factor branch in the ML path
edits.append((
    "                else:\n"
    "                    X = pd.DataFrame([features], columns=ML_FEATURES)\n"
    "                    prediction = self.model.predict(X)[0]\n"
    "                    risk, action, explanation = compute_risk(prediction, rec.dst_ip)\n",

    "                else:\n"
    "                    X = pd.DataFrame([features], columns=ML_FEATURES)\n"
    "                    prediction = self.model.predict(X)[0]\n"
    "                    if RISK_MODEL == '5factor':\n"
    "                        # 5-FACTOR model: all five factors with REAL data\n"
    "                        proba = self.model.predict_proba(X)[0]\n"
    "                        classes = list(self.model.classes_)\n"
    "                        # probability the flow is malicious (not 'normal')\n"
    "                        mal_p = 1.0 - (proba[classes.index('normal')]\n"
    "                                       if 'normal' in classes else 0.0)\n"
    "                        c_rate, f_ratio = self.conn_tracker.features_for(rec.src_ip)\n"
    "                        score, action, breakdown = compute_risk_v2(\n"
    "                            mal_p, rec.dst_ip,\n"
    "                            distinct_dst_hosts_recent=dist_hosts,\n"
    "                            packets_per_sec=c_rate,\n"
    "                            failed_conn_ratio=f_ratio)\n"
    "                        risk = score / 100.0\n"
    "                        explanation = (f\"prediction={prediction} 5F-score={score} \"\n"
    "                                       f\"(ml_p={mal_p:.2f} rate={c_rate} \"\n"
    "                                       f\"fail={f_ratio} fan={dist_hosts}) => {action}\")\n"
    "                    else:\n"
    "                        risk, action, explanation = compute_risk(prediction, rec.dst_ip)\n",
))

for i, (old, new) in enumerate(edits, 1):
    n = src.count(old)
    if n != 1:
        sys.exit(f"ABORT: edit {i} matched {n} times (expected 1). No change.")
    src = src.replace(old, new)

open(F, "w").write(src)
print("Patched simple_switch.py -- selectable 5-factor risk model added.")
