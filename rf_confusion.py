#!/usr/bin/env python3
"""Single confusion matrix for the deployed Random Forest model.
Uses the same dataset/split as train_model_v2.py. Output -> results/rf_confusion_matrix.png"""
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

from train_model_v2 import CSV_PATH, TARGET, FEATURES, add_protocol_features

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
os.makedirs(OUT, exist_ok=True)

df = add_protocol_features(pd.read_csv(CSV_PATH))
X, y = df[FEATURES], df[TARGET]
labels = sorted(y.unique())

# same 70/15/15 split as training
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.30, random_state=42, stratify=y)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp)

model = RandomForestClassifier(n_estimators=200, max_depth=10,
                               class_weight="balanced", random_state=42)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)

cm = confusion_matrix(y_test, y_pred, labels=labels)
print("Confusion matrix (rows=true, cols=pred):")
print("labels:", labels)
print(cm)

fig, ax = plt.subplots(figsize=(6, 5))
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
disp.plot(ax=ax, cmap="Blues", colorbar=True, values_format="d")
ax.set_title("Random Forest — Confusion Matrix (hold-out test set)", fontsize=12, pad=12)
plt.xticks(rotation=20, ha="right")
fig.tight_layout()
out = os.path.join(OUT, "rf_confusion_matrix.png")
fig.savefig(out, dpi=150, bbox_inches="tight")
print(f"\nSaved -> {out}")
