#!/usr/bin/env python3
"""
Diagnostic: trains WITHOUT the "easy" speed/volume features, keeping only
distinct_dst_ports and distinct_dst_hosts_recent. This tells us whether the
real behavioral signal (touching many ports / many hosts) can separate the
classes on its own, without the model cheating on each script's artificial
timing fingerprint.
"""
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE_DIR, "flow_stats.csv")

# Only the "behavioral" features, no speed/volume shortcuts
FEATURES = [
    "distinct_dst_ports",
    "distinct_dst_hosts_recent",
]
TARGET = "label"

def main():
    df = pd.read_csv(CSV_PATH)
    print(f"Loaded {len(df)} rows.")
    print(df[TARGET].value_counts())
    print(f"\nUsing ONLY these features: {FEATURES}\n")

    X = df[FEATURES]
    y = df[TARGET]

    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp)

    model = RandomForestClassifier(
        n_estimators=200, max_depth=10,
        class_weight="balanced", random_state=42)
    model.fit(X_train, y_train)

    print("=== Validation set performance (behavioral features only) ===")
    val_preds = model.predict(X_val)
    print(f"Accuracy: {accuracy_score(y_val, val_preds):.3f}")
    print(classification_report(y_val, val_preds))
    labels = sorted(y.unique())
    print(f"Labels order: {labels}")
    print(confusion_matrix(y_val, val_preds, labels=labels))

    print("\n=== Feature importances ===")
    for feat, imp in sorted(zip(FEATURES, model.feature_importances_),
                            key=lambda x: x[1], reverse=True):
        print(f"  {feat:30s} {imp:.4f}")

    # Also show a quick breakdown: what does distinct_dst_hosts_recent
    # actually look like per class?
    print("\n=== distinct_dst_hosts_recent by class (describe) ===")
    print(df.groupby(TARGET)["distinct_dst_hosts_recent"].describe())

    print("\n=== distinct_dst_ports by class (describe) ===")
    print(df.groupby(TARGET)["distinct_dst_ports"].describe())

if __name__ == "__main__":
    main()
