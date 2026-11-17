#!/usr/bin/env python3
"""
rule_baseline.py -- threshold-rule detector, NO machine learning.

Encodes the kind of static rule a SOC analyst would write by hand:
  * a source contacting >= N distinct hosts in the 10 s window -> lateral_movement
  * a flow touching    >= M distinct destination ports         -> attack (scan)
  * otherwise                                                  -> normal

Output labels use the SAME vocabulary as the ML model, so both detectors feed
the SAME risk engine (risk_engine.compute_risk). Between Configuration C
(rule-based adaptive) and D (ML-driven adaptive) ONLY the detector differs.

Used in two places:
  1. Offline: compare_models.py picks it up as a baseline automatically.
  2. Live:    simple_switch.py calls rule_decide() when NETSHIELD_MODE=rule.

Thresholds can be changed without editing code:
    RULE_HOST_FANOUT=3 RULE_PORT_SCAN=8 python3 rule_baseline.py
"""
import os

import numpy as np

from risk_engine import compute_risk

HOST_FANOUT_THRESHOLD = int(os.environ.get("RULE_HOST_FANOUT", "2"))
PORT_SCAN_THRESHOLD = int(os.environ.get("RULE_PORT_SCAN", "1"))


def rule_classify(distinct_dst_hosts_recent, distinct_dst_ports):
    """Fixed-threshold classification. No learned parameters."""
    if distinct_dst_hosts_recent >= HOST_FANOUT_THRESHOLD:
        return "lateral_movement"
    if distinct_dst_ports >= PORT_SCAN_THRESHOLD:
        return "attack"
    return "normal"


def rule_decide(distinct_dst_hosts_recent, distinct_dst_ports, dst_ip):
    """Live-controller entry point (Configuration C).
    Returns (label, risk, action, explanation) -- same shape the ML path uses."""
    label = rule_classify(distinct_dst_hosts_recent, distinct_dst_ports)
    risk, action, explanation = compute_risk(label, dst_ip)
    return label, risk, action, "RULE " + explanation


class RuleBasedDetector:
    """sklearn-style wrapper so compare_models.py can treat it like a model.
    fit() learns nothing -- thresholds are fixed by hand."""
    def fit(self, X, y=None):
        return self

    def predict(self, X):
        return np.array([
            rule_classify(h, p) for h, p in
            zip(X["distinct_dst_hosts_recent"], X["distinct_dst_ports"])
        ])


if __name__ == "__main__":
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    from train_model_v2 import CSV_PATH, TARGET, FEATURES, add_protocol_features

    df = add_protocol_features(pd.read_csv(CSV_PATH))
    unknown = set(df[TARGET].unique()) - {"normal", "attack", "lateral_movement"}
    if unknown:
        print(f"WARNING: dataset has labels the rule never outputs: {unknown}")

    X, y = df[FEATURES], df[TARGET]
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp)

    print(f"Thresholds: HOST_FANOUT >= {HOST_FANOUT_THRESHOLD}, "
          f"PORT_SCAN >= {PORT_SCAN_THRESHOLD}\n")
    print("=== Feature profile per class (TRAIN split only) ===")
    prof = (X_train.assign(label=y_train)
            .groupby("label")[["distinct_dst_hosts_recent", "distinct_dst_ports"]]
            .agg(["min", "median", "max"]))
    print(prof.to_string(), "\n")

    labels = sorted(y.unique())
    y_pred = RuleBasedDetector().predict(X_test)
    print("=== Rule baseline on hold-out test set ===")
    print(classification_report(y_test, y_pred, labels=labels, zero_division=0))
    print(f"Confusion matrix (order={labels}):")
    print(confusion_matrix(y_test, y_pred, labels=labels))

    print("\n=== Live-path self-test (rule_decide) ===")
    for hosts, ports, dst in [(1, 0, "10.0.0.2"), (2, 1, "10.0.0.3"),
                              (1, 20, "10.0.0.1"), (2, 1, "10.0.0.1")]:
        print(f"hosts={hosts} ports={ports} dst={dst} -> "
              f"{rule_decide(hosts, ports, dst)[3]}")
