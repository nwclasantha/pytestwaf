"""Build a complete set of analytical CSVs from the real scan data
(reports/waf-scan-portal-wazuh-hrclabs-io.csv) plus calibrated ML
predictions, matching the figures and tables in the article.

Outputs to: reports/dataset/
"""
import sys; sys.stdout.reconfigure(encoding="utf-8")
import os, csv, re
from collections import Counter, defaultdict
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.model_selection import StratifiedKFold, cross_val_predict, learning_curve
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score,
    precision_recall_fscore_support, roc_auc_score, brier_score_loss
)
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import StackingClassifier
from sklearn.pipeline import Pipeline

ROOT = r"c:\Users\nwcla\Desktop\pytestwaf"
SRC_CSV = os.path.join(ROOT, "reports", "waf-scan-portal-wazuh-hrclabs-io.csv")
OUT_DIR = os.path.join(ROOT, "reports", "dataset")
os.makedirs(OUT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# 1. Load the real scan and add derived columns
# ---------------------------------------------------------------------------
csv.field_size_limit(10_000_000)

# Read raw rows manually to handle large fields, then build dataframe
with open(SRC_CSV, "r", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    raw = [r for r in reader]

df = pd.DataFrame(raw)
print(f"Loaded {len(df)} scan rows; columns: {list(df.columns)}")

# Drop unresolved rows (no clear ML label)
df = df[df["Check Status"].isin(["blocked", "passed"])].reset_index(drop=True)
df["is_bypass"] = (df["Check Status"] == "passed").astype(int)
df["is_blocked"] = (df["Check Status"] == "blocked").astype(int)

# Derive attack family from the Case name (deterministic keyword extraction)
FAMILY_KEYWORDS = [
    ("xss",   ["xss", "javascript", "script", "html"]),
    ("sqli",  ["sql", "sqli", "union"]),
    ("cmd",   ["cmd", "rce", "exec", "command"]),
    ("lfi",   ["lfi", "rfi", "traversal", "passwd", "etc/"]),
    ("ldap",  ["ldap"]),
    ("xxe",   ["xxe", "xml-injection", "xml"]),
    ("crlf",  ["crlf"]),
    ("mail",  ["mail", "smtp"]),
    ("ssti",  ["template", "ssti"]),
    ("nosql", ["nosql", "mongo"]),
]

def attack_family(case):
    c = (case or "").lower()
    for fam, kws in FAMILY_KEYWORDS:
        if any(kw in c for kw in kws):
            return fam
    return "other"

df["attack_family"] = df["Case"].apply(attack_family)

print("\nattack_family distribution:")
print(df["attack_family"].value_counts())


# ---------------------------------------------------------------------------
# 2. CSV: full scan results with derived columns
# ---------------------------------------------------------------------------
out_full = df[["Payload", "Check Status", "Response Code", "Placeholder",
               "Encoder", "Set", "Case", "Test Result", "attack_family",
               "is_bypass", "is_blocked"]].copy()
# Truncate Payload to keep file size reasonable
out_full["Payload"] = out_full["Payload"].apply(lambda s: (s or "")[:200])
out_full.to_csv(os.path.join(OUT_DIR, "scan_results.csv"), index=False)
print(f"\n[1/9] scan_results.csv: {len(out_full)} rows")


# ---------------------------------------------------------------------------
# 3. CSV: overall summary
# ---------------------------------------------------------------------------
total = len(df)
blocked = int(df["is_blocked"].sum())
bypassed = int(df["is_bypass"].sum())
overall = pd.DataFrame([
    {"metric": "total_test_cases", "value": total},
    {"metric": "blocked", "value": blocked},
    {"metric": "bypassed", "value": bypassed},
    {"metric": "block_rate", "value": round(blocked / total, 4)},
    {"metric": "bypass_rate", "value": round(bypassed / total, 4)},
    {"metric": "unique_cases", "value": df["Case"].nunique()},
    {"metric": "unique_encoders", "value": df["Encoder"].nunique()},
    {"metric": "unique_placeholders", "value": df["Placeholder"].nunique()},
    {"metric": "unique_sets", "value": df["Set"].nunique()},
])
overall.to_csv(os.path.join(OUT_DIR, "summary_overall.csv"), index=False)
print(f"[2/9] summary_overall.csv")


# ---------------------------------------------------------------------------
# 4. CSV: by attack family (Fig. 27 in article)
# ---------------------------------------------------------------------------
fam_summary = df.groupby("attack_family").agg(
    total=("is_bypass", "size"),
    blocked=("is_blocked", "sum"),
    bypassed=("is_bypass", "sum"),
).reset_index()
fam_summary["block_rate"]  = (fam_summary["blocked"]  / fam_summary["total"]).round(4)
fam_summary["bypass_rate"] = (fam_summary["bypassed"] / fam_summary["total"]).round(4)
fam_summary = fam_summary.sort_values("total", ascending=False)
fam_summary.to_csv(os.path.join(OUT_DIR, "summary_by_attack_family.csv"), index=False)
print(f"[3/9] summary_by_attack_family.csv: {len(fam_summary)} families")


# ---------------------------------------------------------------------------
# 5. CSV: by encoder (Fig. 20)
# ---------------------------------------------------------------------------
enc_summary = df.groupby("Encoder").agg(
    total=("is_bypass", "size"),
    blocked=("is_blocked", "sum"),
    bypassed=("is_bypass", "sum"),
).reset_index()
enc_summary["block_rate"]  = (enc_summary["blocked"]  / enc_summary["total"]).round(4)
enc_summary["bypass_rate"] = (enc_summary["bypassed"] / enc_summary["total"]).round(4)
enc_summary = enc_summary.sort_values("total", ascending=False)
enc_summary.to_csv(os.path.join(OUT_DIR, "summary_by_encoder.csv"), index=False)
print(f"[4/9] summary_by_encoder.csv: {len(enc_summary)} encoders")


# ---------------------------------------------------------------------------
# 6. CSV: by placeholder (Fig. 21)
# ---------------------------------------------------------------------------
ph_summary = df.groupby("Placeholder").agg(
    total=("is_bypass", "size"),
    blocked=("is_blocked", "sum"),
    bypassed=("is_bypass", "sum"),
).reset_index()
ph_summary["block_rate"]  = (ph_summary["blocked"]  / ph_summary["total"]).round(4)
ph_summary["bypass_rate"] = (ph_summary["bypassed"] / ph_summary["total"]).round(4)
ph_summary = ph_summary.sort_values("total", ascending=False)
ph_summary.to_csv(os.path.join(OUT_DIR, "summary_by_placeholder.csv"), index=False)
print(f"[5/9] summary_by_placeholder.csv: {len(ph_summary)} placeholders")


# ---------------------------------------------------------------------------
# 7. CSV: encoder × placeholder bypass-rate heatmap (Fig. 22)
# ---------------------------------------------------------------------------
heatmap = df.pivot_table(
    index="Encoder", columns="Placeholder",
    values="is_bypass", aggfunc=["sum", "size"], fill_value=0
)
# Build a flat heatmap CSV
flat_rows = []
for enc in df["Encoder"].unique():
    for ph in df["Placeholder"].unique():
        sub = df[(df["Encoder"] == enc) & (df["Placeholder"] == ph)]
        if len(sub) == 0:
            continue
        flat_rows.append({
            "encoder": enc, "placeholder": ph,
            "total": len(sub),
            "blocked": int(sub["is_blocked"].sum()),
            "bypassed": int(sub["is_bypass"].sum()),
            "bypass_rate": round(sub["is_bypass"].mean(), 4),
        })
heatmap_df = pd.DataFrame(flat_rows).sort_values("bypass_rate", ascending=False)
heatmap_df.to_csv(os.path.join(OUT_DIR, "encoder_x_placeholder_heatmap.csv"), index=False)
print(f"[6/9] encoder_x_placeholder_heatmap.csv: {len(heatmap_df)} cells")


# ---------------------------------------------------------------------------
# 8. CSV: ML predictions on the real data (calibrated stacking ensemble)
#    matching the article's pipeline (RF + GB + MLP base, LR meta, isotonic)
# ---------------------------------------------------------------------------
print("\nTraining calibrated stacking ensemble on real scan features...")
features = ["Encoder", "Placeholder", "Set", "Case", "attack_family"]
X = df[features]
y = df["is_bypass"].values

enc = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
X_enc = enc.fit_transform(X)
print(f"  feature matrix: {X_enc.shape}")

estimators = [
    ("rf", RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)),
    ("gb", GradientBoostingClassifier(n_estimators=100, random_state=42)),
    ("mlp", MLPClassifier(hidden_layer_sizes=(64,), max_iter=300, random_state=42)),
]
stack = StackingClassifier(
    estimators=estimators,
    final_estimator=LogisticRegression(C=0.5, class_weight="balanced", max_iter=300),
    cv=5, stack_method="predict_proba", n_jobs=-1
)
calibrated = CalibratedClassifierCV(stack, cv=5, method="isotonic")

# 5-fold CV out-of-fold predictions
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
y_proba_oof = cross_val_predict(calibrated, X_enc, y, cv=skf,
                                method="predict_proba", n_jobs=-1)[:, 1]
y_pred_oof = (y_proba_oof >= 0.5).astype(int)

# Per-row predictions CSV
pred_df = df[["Encoder", "Placeholder", "Set", "Case", "attack_family",
              "is_bypass", "is_blocked"]].copy()
pred_df["predicted_bypass_probability"] = np.round(y_proba_oof, 4)
pred_df["predicted_label"] = y_pred_oof
pred_df["correct"] = (pred_df["predicted_label"] == pred_df["is_bypass"]).astype(int)
pred_df.to_csv(os.path.join(OUT_DIR, "predictions.csv"), index=False)
print(f"[7/9] predictions.csv: {len(pred_df)} rows")


# ---------------------------------------------------------------------------
# 9. CSV: per-class classification metrics (Fig. 29 / Section VII A)
# ---------------------------------------------------------------------------
prec, rec, f1, sup = precision_recall_fscore_support(y, y_pred_oof, labels=[0, 1])
overall_f1 = f1_score(y, y_pred_oof)
auc = roc_auc_score(y, y_proba_oof)
brier = brier_score_loss(y, y_proba_oof)

cls_df = pd.DataFrame([
    {"class": "blocked",  "precision": round(prec[0], 4), "recall": round(rec[0], 4),
     "f1": round(f1[0], 4), "support": int(sup[0])},
    {"class": "bypassed", "precision": round(prec[1], 4), "recall": round(rec[1], 4),
     "f1": round(f1[1], 4), "support": int(sup[1])},
    {"class": "macro_avg", "precision": round(prec.mean(), 4),
     "recall": round(rec.mean(), 4), "f1": round(f1.mean(), 4), "support": int(sup.sum())},
    {"class": "weighted",  "precision": round(np.average(prec, weights=sup), 4),
     "recall": round(np.average(rec, weights=sup), 4),
     "f1": round(np.average(f1, weights=sup), 4), "support": int(sup.sum())},
    {"class": "binary_overall", "precision": "", "recall": "",
     "f1": round(overall_f1, 4), "support": int(sup.sum())},
])
cls_df.to_csv(os.path.join(OUT_DIR, "classification_report.csv"), index=False)
print(f"[8a] classification_report.csv")

# Confusion matrix CSV
cm = confusion_matrix(y, y_pred_oof, labels=[0, 1])
cm_df = pd.DataFrame(
    cm, index=["actual_blocked", "actual_bypassed"],
    columns=["pred_blocked", "pred_bypassed"]
).reset_index().rename(columns={"index": "row"})
cm_df.to_csv(os.path.join(OUT_DIR, "confusion_matrix.csv"), index=False)
print(f"[8b] confusion_matrix.csv")

# Reliability bins (Fig. 26)
nbins = 10
bin_edges = np.linspace(0, 1, nbins + 1)
bin_idx = np.digitize(y_proba_oof, bin_edges, right=True) - 1
bin_idx = np.clip(bin_idx, 0, nbins - 1)
rel_rows = []
for b in range(nbins):
    mask = bin_idx == b
    if mask.sum() > 0:
        rel_rows.append({
            "bin": b + 1,
            "bin_lower": round(bin_edges[b], 2),
            "bin_upper": round(bin_edges[b + 1], 2),
            "count": int(mask.sum()),
            "mean_predicted_prob": round(float(y_proba_oof[mask].mean()), 4),
            "empirical_bypass_rate": round(float(y[mask].mean()), 4),
        })
rel_df = pd.DataFrame(rel_rows)
rel_df.to_csv(os.path.join(OUT_DIR, "reliability_bins.csv"), index=False)
print(f"[8c] reliability_bins.csv: {len(rel_df)} populated bins")

# Aggregate model summary
summary_metrics = pd.DataFrame([
    {"metric": "model", "value": "calibrated stacking (RF+GB+MLP -> LR), isotonic"},
    {"metric": "n_samples", "value": int(len(y))},
    {"metric": "cv_folds", "value": 5},
    {"metric": "cv_f1", "value": round(overall_f1, 4)},
    {"metric": "cv_roc_auc", "value": round(auc, 4)},
    {"metric": "cv_brier", "value": round(brier, 4)},
    {"metric": "blocked_precision", "value": round(prec[0], 4)},
    {"metric": "blocked_recall",    "value": round(rec[0], 4)},
    {"metric": "blocked_f1",        "value": round(f1[0], 4)},
    {"metric": "bypassed_precision", "value": round(prec[1], 4)},
    {"metric": "bypassed_recall",    "value": round(rec[1], 4)},
    {"metric": "bypassed_f1",        "value": round(f1[1], 4)},
])
summary_metrics.to_csv(os.path.join(OUT_DIR, "model_summary.csv"), index=False)
print(f"[8d] model_summary.csv")

# Compare individual models head-to-head
print("\nTraining individual base models for comparison...")
model_results = []
for name, est in [
    ("RandomForest", RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)),
    ("GradientBoosting", GradientBoostingClassifier(n_estimators=100, random_state=42)),
    ("MLP", MLPClassifier(hidden_layer_sizes=(64,), max_iter=300, random_state=42)),
    ("LogisticRegression", LogisticRegression(C=0.5, max_iter=300, class_weight="balanced")),
]:
    proba = cross_val_predict(est, X_enc, y, cv=skf, method="predict_proba", n_jobs=-1)[:, 1]
    pred = (proba >= 0.5).astype(int)
    model_results.append({
        "model": name,
        "cv_f1": round(f1_score(y, pred), 4),
        "cv_roc_auc": round(roc_auc_score(y, proba), 4),
        "cv_brier": round(brier_score_loss(y, proba), 4),
    })
    print(f"  {name}: F1={model_results[-1]['cv_f1']}")
# Add the calibrated stacking ensemble row
model_results.append({
    "model": "Calibrated Stacking (deployed)",
    "cv_f1": round(overall_f1, 4),
    "cv_roc_auc": round(auc, 4),
    "cv_brier": round(brier, 4),
})
pd.DataFrame(model_results).to_csv(os.path.join(OUT_DIR, "model_comparison.csv"), index=False)
print(f"[9] model_comparison.csv")

# README listing
readme = """# Dataset CSVs

Generated from real scan run reports/waf-scan-portal-wazuh-hrclabs-io.csv.
All numeric values are computed; no synthetic data.

| File | Description | Rows |
|------|-------------|------|
| scan_results.csv | Raw scan with derived attack_family, is_bypass, is_blocked | {n_scan} |
| summary_overall.csv | Total/block/bypass counts and rates | 9 metrics |
| summary_by_attack_family.csv | Block/bypass per attack family (Fig. 27 data) | {n_fam} |
| summary_by_encoder.csv | Block/bypass per encoder (Fig. 20 data) | {n_enc} |
| summary_by_placeholder.csv | Block/bypass per placeholder (Fig. 21 data) | {n_ph} |
| encoder_x_placeholder_heatmap.csv | Bypass-rate cross-tab (Fig. 22 data) | {n_hm} |
| predictions.csv | OOF calibrated probabilities + predicted labels per case | {n_pred} |
| classification_report.csv | Per-class precision/recall/F1 (Fig. 29 data) | 5 |
| confusion_matrix.csv | Aggregated confusion matrix (Fig. 25 data) | 2 |
| reliability_bins.csv | 10-bin reliability diagram (Fig. 26 data) | up to 10 |
| model_summary.csv | Headline metrics of the deployed ensemble | 12 |
| model_comparison.csv | F1/AUC/Brier per base model + deployed ensemble | 5 |
""".format(
    n_scan=len(out_full), n_fam=len(fam_summary), n_enc=len(enc_summary),
    n_ph=len(ph_summary), n_hm=len(heatmap_df), n_pred=len(pred_df),
)
with open(os.path.join(OUT_DIR, "README.md"), "w", encoding="utf-8") as f:
    f.write(readme)

print(f"\nAll CSVs written to: {OUT_DIR}")
print("\nKey metrics from this real-data run:")
print(f"  Total cases: {total}")
print(f"  Blocked: {blocked} ({blocked/total*100:.1f}%)")
print(f"  Bypassed: {bypassed} ({bypassed/total*100:.1f}%)")
print(f"  Calibrated ensemble CV F1: {overall_f1:.4f}")
print(f"  Calibrated ensemble CV AUC: {auc:.4f}")
print(f"  Calibrated ensemble Brier: {brier:.4f}")
