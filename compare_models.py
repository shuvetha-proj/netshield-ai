#!/usr/bin/env python3
"""
compare_models.py -- Objective 4: detection model comparison.

Uses the SAME dataset (flow_stats.csv), the SAME 6 behavioural features and
the SAME 70/15/15 stratified split (random_state=42) as train_model_v2.py,
so the Random Forest numbers line up with the deployed model.

Detectors compared:
  * Random Forest   (deployed model, identical hyper-parameters)
  * Decision Tree   (single interpretable tree)
  * XGBoost         (only if the xgboost package is installed)
  * Threshold rule  (rule_baseline.py, NO ML -- only if that file exists)

Metrics: accuracy, macro precision / recall / F1, plus binary
normal-vs-malicious FPR (benign flows wrongly flagged) and FNR (malicious
flows missed). Reported on the hold-out test set AND as 5-fold stratified
cross-validation (mean +/- std), because the hold-out set is small.

Does NOT modify ransomware_model_v2.joblib.  Outputs -> results/
"""
import os
import warnings

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, classification_report)

from train_model_v2 import CSV_PATH, TARGET, FEATURES, add_protocol_features

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAVE_MPL = True
except ImportError:
    HAVE_MPL = False

warnings.filterwarnings("ignore")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(OUT_DIR, exist_ok=True)
NORMAL = "normal"
SEED = 42


class XGBWrapper:
    """XGBoost needs integer labels; wrap it so it takes/returns strings."""
    def __init__(self):
        from xgboost import XGBClassifier
        self.le = LabelEncoder()
        self.model = XGBClassifier(n_estimators=200, max_depth=6,
                                   learning_rate=0.1, random_state=SEED)

    def fit(self, X, y):
        self.model.fit(X, self.le.fit_transform(y))
        return self

    def predict(self, X):
        return self.le.inverse_transform(
            np.asarray(self.model.predict(X)).astype(int))


def build_detectors():
    d = {
        "Random Forest": lambda: RandomForestClassifier(
            n_estimators=200, max_depth=10, class_weight="balanced",
            random_state=SEED),
        "Decision Tree": lambda: DecisionTreeClassifier(
            max_depth=10, class_weight="balanced", random_state=SEED),
    }
    try:
        import xgboost  # noqa: F401
        d["XGBoost"] = XGBWrapper
    except ImportError:
        print("[info] xgboost not installed -- skipped (optional)")
    try:
        from rule_baseline import RuleBasedDetector
        d["Threshold rule (no ML)"] = RuleBasedDetector
    except ImportError:
        print("[info] rule_baseline.py not found -- rule baseline skipped")
    return d


def binary_rates(y_true, y_pred):
    t = np.asarray(y_true) != NORMAL
    p = np.asarray(y_pred) != NORMAL
    tp = int(np.sum(t & p)); tn = int(np.sum(~t & ~p))
    fp = int(np.sum(~t & p)); fn = int(np.sum(t & ~p))
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return fpr, fnr


def score(y_true, y_pred, labels):
    fpr, fnr = binary_rates(y_true, y_pred)
    kw = dict(labels=labels, average="macro", zero_division=0)
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, **kw),
        "recall": recall_score(y_true, y_pred, **kw),
        "f1": f1_score(y_true, y_pred, **kw),
        "fpr": fpr,
        "fnr": fnr,
    }


def cross_val(factory, X, y, labels):
    k = int(min(5, y.value_counts().min()))
    if k < 2:
        return None
    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=SEED)
    out = []
    for tr, te in skf.split(X, y):
        m = factory().fit(X.iloc[tr], y.iloc[tr])
        out.append(score(y.iloc[te], m.predict(X.iloc[te]), labels))
    return pd.DataFrame(out)


def plot_confusion(cms, labels, path):
    n = len(cms)
    fig, axes = plt.subplots(1, n, figsize=(4.2 * n, 4))
    axes = np.atleast_1d(axes)
    for ax, (name, cm) in zip(axes, cms.items()):
        ax.imshow(cm, cmap="Blues")
        ax.set_title(name, fontsize=10)
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
        ax.set_yticks(range(len(labels)))
        ax.set_yticklabels(labels, fontsize=8)
        ax.set_xlabel("Predicted"); ax.set_ylabel("True")
        thr = cm.max() / 2 if cm.max() else 0
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(j, i, cm[i, j], ha="center", va="center",
                        color="white" if cm[i, j] > thr else "black")
    fig.suptitle("Confusion matrices -- hold-out test set")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_metrics(res, path):
    metrics = ["test_accuracy", "test_precision", "test_recall",
               "test_f1", "test_fpr"]
    names = ["Accuracy", "Precision", "Recall", "F1", "FPR (lower=better)"]
    x = np.arange(len(metrics))
    w = 0.8 / len(res)
    fig, ax = plt.subplots(figsize=(10, 4.5))
    for i, (_, r) in enumerate(res.iterrows()):
        ax.bar(x - 0.4 + w / 2 + i * w, [r[m] for m in metrics], w,
               label=r["model"])
    ax.set_xticks(x); ax.set_xticklabels(names)
    ax.set_ylim(0, 1.05); ax.set_ylabel("Score")
    ax.set_title("Detector comparison -- hold-out test set")
    ax.grid(axis="y", alpha=0.3); ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def main():
    df = add_protocol_features(pd.read_csv(CSV_PATH))
    X, y = df[FEATURES], df[TARGET]
    labels = sorted(y.unique())
    print(f"Dataset: {len(df)} flows | classes: {dict(y.value_counts())}")

    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=SEED, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=SEED, stratify=y_temp)
    print(f"Split (identical to train_model_v2.py): train={len(X_train)} "
          f"val={len(X_val)} test={len(X_test)}\n")

    detectors = build_detectors()
    rows, cms, fitted, report = [], {}, {}, []

    for name, factory in detectors.items():
        model = factory().fit(X_train, y_train)
        fitted[name] = model
        y_pred = model.predict(X_test)
        s = score(y_test, y_pred, labels)
        cms[name] = confusion_matrix(y_test, y_pred, labels=labels)
        cv = cross_val(factory, X, y, labels)

        row = {"model": name}
        row.update({f"test_{k}": round(v, 4) for k, v in s.items()})
        for k in s:
            row[f"cv_{k}_mean"] = round(cv[k].mean(), 4) if cv is not None else np.nan
            row[f"cv_{k}_std"] = round(cv[k].std(), 4) if cv is not None else np.nan
        rows.append(row)

        report += [f"===== {name} (hold-out test set) =====",
                   classification_report(y_test, y_pred, labels=labels,
                                         zero_division=0),
                   f"Confusion matrix (rows=true, cols=pred, order={labels}):",
                   str(cms[name]), ""]

    res = pd.DataFrame(rows)
    res.to_csv(os.path.join(OUT_DIR, "model_comparison.csv"), index=False)
    with open(os.path.join(OUT_DIR, "model_report.txt"), "w") as f:
        f.write("\n".join(report))

    imp = {"feature": FEATURES}
    for name, m in fitted.items():
        if hasattr(m, "feature_importances_"):
            imp[name] = np.round(m.feature_importances_, 4)
    pd.DataFrame(imp).to_csv(os.path.join(OUT_DIR, "feature_importances.csv"),
                             index=False)
    with open(os.path.join(OUT_DIR, "decision_tree_rules.txt"), "w") as f:
        f.write(export_text(fitted["Decision Tree"], feature_names=FEATURES))

    print("\n".join(report))
    print("=== SUMMARY (test = hold-out set; CV = 5-fold mean +/- std) ===")
    for r in rows:
        print(f"{r['model']:24s} acc={r['test_accuracy']:.3f} "
              f"P={r['test_precision']:.3f} R={r['test_recall']:.3f} "
              f"F1={r['test_f1']:.3f} FPR={r['test_fpr']:.3f} "
              f"FNR={r['test_fnr']:.3f} | CV F1={r['cv_f1_mean']:.3f}"
              f"+/-{r['cv_f1_std']:.3f} CV FPR={r['cv_fpr_mean']:.3f}")

    if HAVE_MPL:
        plot_confusion(cms, labels, os.path.join(OUT_DIR, "confusion_matrices.png"))
        plot_metrics(res, os.path.join(OUT_DIR, "model_comparison.png"))
        print(f"\nCharts -> {OUT_DIR}/confusion_matrices.png, model_comparison.png")
    else:
        print("\n[info] matplotlib missing -- CSV/TXT written, charts skipped")
    print(f"Tables -> {OUT_DIR}/model_comparison.csv, model_report.txt, "
          f"feature_importances.csv, decision_tree_rules.txt")


if __name__ == "__main__":
    main()
