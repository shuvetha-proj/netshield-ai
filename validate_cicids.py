#!/usr/bin/env python3
"""
validate_cicids.py -- Review 3: validate the detection methodology on the
PUBLIC CIC-IDS2017 dataset (real-world traffic), not just our lab data.

We apply the SAME approach as our project -- a Random Forest classifier on
flow features -- to real CIC-IDS2017 traffic (PortScan attack + benign).
This shows our method generalises beyond the synthetic testbed.

Output -> results/cicids_validation.png + results/cicids_report.txt
"""
import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, ConfusionMatrixDisplay,
                             classification_report)

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "results"); os.makedirs(OUT, exist_ok=True)
CIC = os.path.join(BASE, "cicids2017")
SEED = 42

# Use the PortScan file (attack type closest to our scanning / lateral probing)
DATA_FILE = os.path.join(CIC, "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")

print("Loading CIC-IDS2017 PortScan data (real-world traffic)...")
df = pd.read_csv(DATA_FILE)
df.columns = df.columns.str.strip()   # CIC columns have leading spaces

# Label column is the last one
label_col = df.columns[-1]
print(f"Total flows: {len(df):,} | classes: {dict(df[label_col].value_counts())}")

# --- clean: CIC-IDS2017 has infinities and NaNs in some flow-rate columns ---
feature_cols = [c for c in df.columns if c != label_col]
X = df[feature_cols].copy()
X = X.replace([np.inf, -np.inf], np.nan)
X = X.apply(pd.to_numeric, errors="coerce")
X = X.fillna(0)
y = df[label_col].astype(str).str.strip()
# binary: BENIGN vs attack
y = y.apply(lambda v: "BENIGN" if v == "BENIGN" else "ATTACK")
labels = ["BENIGN", "ATTACK"]
print(f"After cleaning: {X.shape[1]} features, {len(X):,} flows")
print(f"Binary classes: {dict(y.value_counts())}\n")

# --- train/test split (same 70/30 style, stratified) ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.30, random_state=SEED, stratify=y)
print(f"Train: {len(X_train):,}  Test: {len(X_test):,}")

# --- same Random Forest approach as our project ---
print("Training Random Forest (same approach as our project)...")
model = RandomForestClassifier(n_estimators=100, max_depth=15,
                               class_weight="balanced", random_state=SEED, n_jobs=-1)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, pos_label="ATTACK")
rec = recall_score(y_test, y_pred, pos_label="ATTACK")
f1 = f1_score(y_test, y_pred, pos_label="ATTACK")
cm = confusion_matrix(y_test, y_pred, labels=labels)
tn, fp, fn, tp = cm.ravel()
fpr = fp / (fp + tn) if (fp+tn) else 0
fnr = fn / (fn + tp) if (fn+tp) else 0

report = []
report.append("CIC-IDS2017 VALIDATION (public real-world dataset)")
report.append("Attack type: PortScan   |   Approach: Random Forest on flow features")
report.append("="*60)
report.append(f"Total flows analysed : {len(df):,}")
report.append(f"Features used        : {X.shape[1]}")
report.append(f"Train / Test         : {len(X_train):,} / {len(X_test):,}")
report.append("")
report.append(f"Accuracy  : {acc:.4f}")
report.append(f"Precision : {prec:.4f}")
report.append(f"Recall    : {rec:.4f}")
report.append(f"F1-score  : {f1:.4f}")
report.append(f"FPR       : {fpr:.4f}")
report.append(f"FNR       : {fnr:.4f}")
report.append("")
report.append("Confusion matrix (rows=true, cols=pred, order=[BENIGN, ATTACK]):")
report.append(str(cm))
report.append("")
report.append(classification_report(y_test, y_pred, labels=labels))

# --- top features (what the model relies on) ---
imp = sorted(zip(feature_cols, model.feature_importances_), key=lambda x:-x[1])[:10]
report.append("Top 10 most important features:")
for f, v in imp:
    report.append(f"  {f:35s} {v:.4f}")

rep = "\n".join(report)
print("\n" + rep)
open(os.path.join(OUT, "cicids_report.txt"), "w").write(rep + "\n")

# --- figure: confusion matrix + metrics ---
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels).plot(
    ax=ax1, cmap="Blues", colorbar=False, values_format="d")
ax1.set_title("CIC-IDS2017 (PortScan) — Confusion Matrix", fontsize=12)

metrics = ["Accuracy","Precision","Recall","F1"]
vals = [acc, prec, rec, f1]
bars = ax2.bar(metrics, vals, color=["#2f81f7","#1f9d55","#e3a008","#8b5cf6"])
ax2.set_ylim(0, 1.05); ax2.set_ylabel("Score")
ax2.set_title("Detection Performance on Real-World Traffic", fontsize=12)
for b, v in zip(bars, vals):
    ax2.text(b.get_x()+b.get_width()/2, v+0.01, f"{v:.3f}", ha="center", fontweight="bold")
ax2.grid(axis="y", alpha=0.3)
fig.suptitle(f"Validation on Public CIC-IDS2017 Dataset ({len(df):,} real flows)",
             fontsize=13, fontweight="bold")
fig.tight_layout()
fig.savefig(os.path.join(OUT, "cicids_validation.png"), dpi=150, bbox_inches="tight")
print(f"\nFigure -> {OUT}/cicids_validation.png")
print(f"Report -> {OUT}/cicids_report.txt")
