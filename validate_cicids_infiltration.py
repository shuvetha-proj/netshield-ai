#!/usr/bin/env python3
"""
Validate the detection approach on CIC-IDS2017 INFILTRATION traffic --
the attack type closest to our project's theme (an attacker moving inside
the network, like ransomware lateral movement).
Output -> results/cicids_infiltration.png + report
"""
import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, ConfusionMatrixDisplay,
                             classification_report)

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "results"); os.makedirs(OUT, exist_ok=True)
CIC = os.path.join(BASE, "cicids2017")
SEED = 42
DATA = os.path.join(CIC, "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv")

print("Loading CIC-IDS2017 INFILTRATION data (lateral-movement style attack)...")
df = pd.read_csv(DATA)
df.columns = df.columns.str.strip()
label_col = df.columns[-1]
print(f"Total flows: {len(df):,} | classes: {dict(df[label_col].value_counts())}")

feature_cols = [c for c in df.columns if c != label_col]
X = df[feature_cols].replace([np.inf,-np.inf], np.nan).apply(pd.to_numeric, errors="coerce").fillna(0)
y = df[label_col].astype(str).str.strip().apply(lambda v: "BENIGN" if v=="BENIGN" else "ATTACK")
labels = ["BENIGN","ATTACK"]
print(f"Binary classes: {dict(y.value_counts())}")

# Infiltration is HIGHLY imbalanced (very few attack flows) -- this is the
# honest, harder test. Stratify to keep both classes in train and test.
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.30, random_state=SEED, stratify=y)
print(f"Train: {len(X_train):,}  Test: {len(X_test):,}")

model = RandomForestClassifier(n_estimators=100, max_depth=15,
                               class_weight="balanced", random_state=SEED, n_jobs=-1)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)

acc=accuracy_score(y_test,y_pred)
prec=precision_score(y_test,y_pred,pos_label="ATTACK",zero_division=0)
rec=recall_score(y_test,y_pred,pos_label="ATTACK",zero_division=0)
f1=f1_score(y_test,y_pred,pos_label="ATTACK",zero_division=0)
cm=confusion_matrix(y_test,y_pred,labels=labels)

rep=[]
rep.append("CIC-IDS2017 VALIDATION — INFILTRATION (lateral-movement style)")
rep.append("="*60)
rep.append(f"Total flows : {len(df):,}")
rep.append(f"Classes     : {dict(y.value_counts())}")
rep.append(f"Note: infiltration is highly imbalanced (few attack flows) -- a harder, honest test.")
rep.append("")
rep.append(f"Accuracy  : {acc:.4f}")
rep.append(f"Precision : {prec:.4f}")
rep.append(f"Recall    : {rec:.4f}")
rep.append(f"F1-score  : {f1:.4f}")
rep.append("")
rep.append("Confusion matrix (rows=true, cols=pred, [BENIGN, ATTACK]):")
rep.append(str(cm))
rep.append("")
rep.append(classification_report(y_test,y_pred,labels=labels,zero_division=0))
report="\n".join(rep)
print("\n"+report)
open(os.path.join(OUT,"cicids_infiltration_report.txt"),"w").write(report+"\n")

fig,ax=plt.subplots(figsize=(6,5))
ConfusionMatrixDisplay(confusion_matrix=cm,display_labels=labels).plot(ax=ax,cmap="Greens",colorbar=True,values_format="d")
ax.set_title(f"CIC-IDS2017 Infiltration — Confusion Matrix\n(lateral-movement style, {len(df):,} flows)",fontsize=11)
fig.tight_layout()
fig.savefig(os.path.join(OUT,"cicids_infiltration.png"),dpi=150,bbox_inches="tight")
print(f"\nFigure -> {OUT}/cicids_infiltration.png")
