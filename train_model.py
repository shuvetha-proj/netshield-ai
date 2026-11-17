#!/usr/bin/env python3
"""
Trains a classifier on flow_stats.csv to distinguish normal traffic from
port-scan and lateral-movement attacks.

Usage: python3 train_model.py
"""
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE_DIR, "flow_stats.csv")
MODEL_PATH = os.path.join(BASE_DIR, "ransomware_model.joblib")

FEATURES = [
    "duration_sec",
    "packet_count",
    "byte_count",
    "distinct_dst_ports",
    "packets_per_sec",
    "distinct_dst_hosts_recent",
]
TARGET = "label"

def main():
    print(f"Loading {CSV_PATH} ...")
    df = pd.read_csv(CSV_PATH)
    print(f"Loaded {len(df)} rows.")
    print(df[TARGET].value_counts())

    X = df[FEATURES]
    y = df[TARGET]

    # Split: 70% train, 15% validation, 15% test, stratified so each split
    # has a fair share of every class.
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp)

    print(f"\nTrain: {len(X_train)}  Validation: {len(X_val)}  Test: {len(X_test)}")

    # class_weight='balanced' compensates for lateral_movement having more
    # rows than normal/attack in this dataset.
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        class_weight="balanced",
        random_state=42,
    )
    model.fit(X_train, y_train)

    print("\n=== Validation set performance ===")
    val_preds = model.predict(X_val)
    print(f"Accuracy: {accuracy_score(y_val, val_preds):.3f}")
    print(classification_report(y_val, val_preds))
    print("Confusion matrix (rows=actual, cols=predicted):")
    labels = sorted(y.unique())
    print(f"Labels order: {labels}")
    print(confusion_matrix(y_val, val_preds, labels=labels))

    print("\n=== Final test set performance (held out, untouched until now) ===")
    test_preds = model.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, test_preds):.3f}")
    print(classification_report(y_test, test_preds))
    print("Confusion matrix (rows=actual, cols=predicted):")
    print(f"Labels order: {labels}")
    print(confusion_matrix(y_test, test_preds, labels=labels))

    print("\n=== Feature importances ===")
    importances = sorted(
        zip(FEATURES, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    for feat, imp in importances:
        print(f"  {feat:30s} {imp:.4f}")

    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")

if __name__ == "__main__":
    main()
