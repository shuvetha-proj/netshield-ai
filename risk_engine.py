#!/usr/bin/env python3
"""
Risk-scoring layer: combines an ML prediction with destination criticality
to produce a risk score and a response tier (MONITOR / RESTRICT / QUARANTINE).

Updated for the 8-host VLAN topology (Review 3): the Server segment (VLAN30)
has two critical assets -- File Server (10.0.0.3) and Database (10.0.0.5).
Guest (10.0.0.4) is excluded -- it is fully blocked by static ACL.
"""

# Host IPs and their criticality tier (by VLAN segment).
HOST_CRITICALITY = {
    "10.0.0.1": ("HR", 1.0),          # VLAN10
    "10.0.0.2": ("Finance", 1.2),     # VLAN20
    "10.0.0.3": ("FileServer", 1.5),  # VLAN30 - critical asset
    "10.0.0.5": ("Database", 1.5),    # VLAN30 - critical asset
    "10.0.0.6": ("IoT-1", 1.0),       # VLAN50
    "10.0.0.7": ("IoT-2", 1.0),       # VLAN50
    "10.0.0.8": ("Admin", 1.1),       # VLAN60
}

BASE_RISK = {
    "normal": 0.0,
    "attack": 0.45,
    "lateral_movement": 0.55,
}

RESTRICT_THRESHOLD = 0.3
QUARANTINE_THRESHOLD = 0.7


def compute_risk(predicted_label, dst_ip):
    """Returns (risk_score, action, explanation)."""
    base = BASE_RISK.get(predicted_label, 0.0)
    dst_name, multiplier = HOST_CRITICALITY.get(dst_ip, ("Unknown", 1.0))

    risk = min(base * multiplier, 1.0)

    if risk < RESTRICT_THRESHOLD:
        action = "MONITOR"
    elif risk < QUARANTINE_THRESHOLD:
        action = "RESTRICT"
    else:
        action = "QUARANTINE"

    explanation = (
        f"prediction={predicted_label} (base_risk={base}) "
        f"-> dst={dst_name} (multiplier={multiplier}) "
        f"=> risk={risk:.2f} => {action}"
    )
    return risk, action, explanation


if __name__ == "__main__":
    print("=== Risk engine self-test (8-host) ===\n")
    for label in BASE_RISK:
        for dst_ip, (name, _) in HOST_CRITICALITY.items():
            risk, action, explanation = compute_risk(label, dst_ip)
            print(explanation)
        print()
