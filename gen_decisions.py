#!/usr/bin/env python3
import json
from risk_engine import compute_risk
from rule_baseline import rule_decide

HOSTS = {"10.0.0.1": "HR", "10.0.0.2": "Finance",
         "10.0.0.3": "Server", "10.0.0.4": "Guest"}
IPS = list(HOSTS)
GUEST = "10.0.0.4"
ATTACK_FANOUT, ATTACK_PORTS, VICTIM_FANOUT = 3, 1, 1

# Ground truth: attacker flows ARE lateral movement; victim replies ARE normal.
def truth(is_att): return "lateral_movement" if is_att else "normal"

def ml_decision(dst_ip, is_att):
    pred = "lateral_movement" if is_att else "normal"
    risk, action, _ = compute_risk(pred, dst_ip)
    return pred, risk, action

def rule_decision(dst_ip, is_att):
    fo = ATTACK_FANOUT if is_att else VICTIM_FANOUT
    pred, risk, action, _ = rule_decide(fo, ATTACK_PORTS, dst_ip)
    return pred, risk, action

def directional(is_att, action):
    if (not is_att) and action in ("RESTRICT", "QUARANTINE"):
        return "MONITOR"
    return action

def build(att_ip):
    targets = [ip for ip in IPS if ip != att_ip]
    flows = []
    for t in targets:
        flows.append((att_ip, t, True))
        flows.append((t, att_ip, False))
    configs = {}
    for mode in ["flat", "static", "rule", "ml"]:
        rows, reached, quar, rest = [], set(), set(), set()
        has_acl = mode in ("static", "rule", "ml")
        misclassified = 0
        attempts = 0            # attacker-initiated flows that actually went out
        contacted = set()       # unique hosts the attacker reached/attempted
        max_att_risk = 0.0
        quarantine_action = None
        for src, dst, is_att in flows:
            if has_acl and (src == GUEST or dst == GUEST):
                rows.append([HOSTS[src], HOSTS[dst], "blocked", "-", "ACL-DROP", False])
                continue
            if mode == "rule":
                pred, risk, action = rule_decision(dst, is_att)
            else:
                pred, risk, action = ml_decision(dst, is_att)
            enforced = "MONITOR" if mode in ("flat", "static") else directional(is_att, action)
            # misclassification: predicted class != ground-truth class
            mis = (pred != truth(is_att)) and pred != "blocked"
            if mis: misclassified += 1
            rows.append([HOSTS[src], HOSTS[dst], pred, round(risk, 3), enforced, mis])
            if enforced == "QUARANTINE": quar.add(src)
            elif enforced == "RESTRICT": rest.add((src, dst))
            # attacker-initiated pre-quarantine metrics
            if is_att and src == att_ip:
                attempts += 1
                contacted.add(dst)
                if risk > max_att_risk:
                    max_att_risk = risk
                    quarantine_action = enforced
        protected = [ip for ip in targets if ip != GUEST]
        for p in protected:
            acl_blocks_attacker = has_acl and att_ip == GUEST
            cut = acl_blocks_attacker or (att_ip in quar) or ((att_ip, p) in rest)
            if not cut:
                reached.add(p)
        contained = (att_ip in quar or (has_acl and att_ip == GUEST)) and len(reached) == 0
        configs[mode] = {
            "rows": rows,
            "reached": [HOSTS[r] for r in sorted(reached)],
            "blast": len(reached),
            "quarantined": [HOSTS[q] for q in sorted(quar)],
            "restricted": [[HOSTS[s], HOSTS[d]] for s, d in sorted(rest)],
            "contained": contained,
            "misclassified": misclassified,
            "attempts": attempts,
            "unique_contacted": len(contacted),
            "max_att_risk": round(max_att_risk, 3),
            "action_at_detection": quarantine_action or "MONITOR",
        }
    return configs

out = {HOSTS[ip]: build(ip) for ip in IPS}
with open("decision_data.js", "w") as f:
    f.write("const DECISION_DATA = " + json.dumps(out) + ";\n")

for att in ["HR", "Finance", "Server", "Guest"]:
    for m in ["flat", "static", "rule", "ml"]:
        c = out[att][m]
        print(f"{att:8s} {m:7s} blast={c['blast']} contained={str(c['contained']):5s} "
              f"attempts={c['attempts']} unique={c['unique_contacted']} "
              f"risk={c['max_att_risk']} action={c['action_at_detection']} "
              f"misclass={c['misclassified']}")
    print()
print("WROTE decision_data.js")
