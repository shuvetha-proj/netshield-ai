#!/usr/bin/env python3
"""
risk_engine_v2.py -- 5-term weighted risk model (0-100).

Used LIVE by the controller when RISK_MODEL=5factor (simple_switch.py).
RISK_MODEL=2factor falls back to the simpler risk_engine.py.

Terms (weights sum to 1.0):
  1. ML attack probability   -- 1 - P(normal) from model.predict_proba
  2. Connection rate         -- from connection_tracker.py, normalised by PPS_CEIL
  3. Failed-connection ratio -- from connection_tracker.py (5-tuple state,
                                retransmitted SYNs counted as one attempt)
  4. Unique destinations     -- fan-out (distinct_dst_hosts_recent)
  5. Asset criticality       -- destination weight, 8-host VLAN topology

Tiers: score < 30 -> MONITOR, 30-70 -> RESTRICT, >= 70 -> QUARANTINE.
Scope policy lives in the controller, not here: a single-target scan is
capped at pair-level RESTRICT; host-wide QUARANTINE needs multi-host initiation.
"""

# --- term weights (sum = 1.0) ----------------------------------------------
W_ML        = 0.35   # ML attack probability   (fully implemented)
W_CONNRATE  = 0.15   # connection rate         (connection_tracker.py)
W_FAILRATIO = 0.15   # failed-connection ratio (connection_tracker.py)
W_FANOUT    = 0.20   # unique destinations     (fully implemented)
W_CRIT      = 0.15   # asset criticality       (fully implemented)

CRITICALITY = {  # destination criticality, 0-1 (critical assets = 1.0)
    # same tiers as risk_engine.py multipliers, divided by 1.5
    "10.0.0.1": ("HR",         1.0 / 1.5),  # VLAN10
    "10.0.0.2": ("Finance",    1.2 / 1.5),  # VLAN20
    "10.0.0.3": ("FileServer", 1.5 / 1.5),  # VLAN30 - critical asset
    "10.0.0.4": ("Guest",      1.0 / 1.5),  # VLAN40 - also statically blocked
    "10.0.0.5": ("Database",   1.5 / 1.5),  # VLAN30 - critical asset
    "10.0.0.6": ("IoT-1",      1.0 / 1.5),  # VLAN50
    "10.0.0.7": ("IoT-2",      1.0 / 1.5),  # VLAN50
    "10.0.0.8": ("Admin",      1.1 / 1.5),  # VLAN60
}

# behavioural ceilings used to normalise raw features to 0-1
FANOUT_CEIL = 3.0        # contacting >=3 hosts = full fan-out signal
PPS_CEIL    = 20.0       # packets/sec that counts as "max" connection rate

RESTRICT_THRESHOLD = 30.0
QUARANTINE_THRESHOLD = 70.0

# which terms are real vs pending instrumentation (for honest reporting)
TERM_STATUS = {
    "ml_probability": "implemented",
    "connection_rate": "implemented (connection_tracker.py)",
    "failed_conn_ratio": "implemented (connection_tracker.py)",
    "unique_destinations": "implemented",
    "asset_criticality": "implemented",
}


def _clamp01(x):
    return max(0.0, min(1.0, x))


def compute_risk_v2(ml_probability, dst_ip,
                    distinct_dst_hosts_recent=1,
                    packets_per_sec=0.0,
                    failed_conn_ratio=None):
    """
    ml_probability: model's confidence this flow is malicious, 0-1.
    Returns (score_0_100, action, breakdown dict).
    """
    # term 1: ML probability
    t_ml = _clamp01(ml_probability)

    # term 2: connection rate (from connection_tracker)
    t_conn = _clamp01(packets_per_sec / PPS_CEIL)

    # term 3: failed-connection ratio (from connection_tracker)
    t_fail = 0.0 if failed_conn_ratio is None else _clamp01(failed_conn_ratio)

    # term 4: unique destinations (fan-out)
    t_fan = _clamp01(distinct_dst_hosts_recent / FANOUT_CEIL)

    # term 5: asset criticality of the destination
    _, t_crit = CRITICALITY.get(dst_ip, ("Unknown", 1.0 / 1.5))

    score = 100.0 * (
        W_ML * t_ml +
        W_CONNRATE * t_conn +
        W_FAILRATIO * t_fail +
        W_FANOUT * t_fan +
        W_CRIT * t_crit
    )
    score = round(score, 1)

    if score < RESTRICT_THRESHOLD:
        action = "MONITOR"
    elif score < QUARANTINE_THRESHOLD:
        action = "RESTRICT"
    else:
        action = "QUARANTINE"

    breakdown = {
        "ml_probability": round(W_ML * t_ml * 100, 1),
        "connection_rate": round(W_CONNRATE * t_conn * 100, 1),
        "failed_conn_ratio": round(W_FAILRATIO * t_fail * 100, 1),
        "unique_destinations": round(W_FANOUT * t_fan * 100, 1),
        "asset_criticality": round(W_CRIT * t_crit * 100, 1),
    }
    return score, action, breakdown


# probability a 'lateral_movement' / 'attack' prediction maps to (for the demo,
# since the deployed model outputs a label; v3 would use predict_proba).
LABEL_PROB = {"normal": 0.05, "attack": 0.80, "lateral_movement": 0.90}


if __name__ == "__main__":
    print("=== 5-term risk model (risk_engine_v2) ===\n")
    print("Term weights:")
    for k, w in [("ML probability", W_ML), ("Connection rate", W_CONNRATE),
                 ("Failed-conn ratio", W_FAILRATIO),
                 ("Unique destinations", W_FANOUT), ("Asset criticality", W_CRIT)]:
        print(f"  {k:22s} {w:.2f}")
    print(f"  {'TOTAL':22s} {W_ML+W_CONNRATE+W_FAILRATIO+W_FANOUT+W_CRIT:.2f}\n")

    print("Term instrumentation status:")
    for k, v in TERM_STATUS.items():
        print(f"  {k:22s} {v}")
    print()

    # demo scenarios mirroring the live attack
    scenarios = [
        ("Normal ping to Finance",        "normal",           "10.0.0.2", 1, 1.3),
        ("Lateral move -> Finance",       "lateral_movement", "10.0.0.2", 3, 12.0),
        ("Lateral move -> Server (crit)", "lateral_movement", "10.0.0.3", 3, 12.0),
        ("Port scan -> HR",               "attack",           "10.0.0.1", 1, 15.0),
    ]
    print(f"{'Scenario':34s} {'score':>6s}  {'action':10s}  breakdown")
    for name, label, dst, fan, pps in scenarios:
        prob = LABEL_PROB[label]
        score, action, bd = compute_risk_v2(prob, dst,
                                             distinct_dst_hosts_recent=fan,
                                             packets_per_sec=pps)
        parts = " ".join(f"{k.split('_')[0]}={v}" for k, v in bd.items())
        print(f"{name:34s} {score:6.1f}  {action:10s}  {parts}")
