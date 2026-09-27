"""Cross-check every derived CSV against the source scan to confirm
100% alignment with the actual data."""
import sys; sys.stdout.reconfigure(encoding="utf-8")
import os, csv, hashlib, re
import pandas as pd

ROOT = r"c:\Users\nwcla\Desktop\pytestwaf"
SRC_CSV = os.path.join(ROOT, "reports", "waf-scan-portal-wazuh-hrclabs-io.csv")
D = os.path.join(ROOT, "reports", "dataset")

csv.field_size_limit(10_000_000)

# --- Load source scan ---
with open(SRC_CSV, "r", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    raw = [r for r in reader]
src = pd.DataFrame(raw)
src_blocked = (src["Check Status"] == "blocked").sum()
src_passed  = (src["Check Status"] == "passed").sum()
src_unres   = (src["Check Status"] == "unresolved").sum()
print(f"SOURCE scan:")
print(f"  total rows:      {len(src)}")
print(f"  blocked:         {src_blocked}")
print(f"  passed (bypass): {src_passed}")
print(f"  unresolved:      {src_unres}")

# --- Load derived datasets ---
scan_results          = pd.read_csv(os.path.join(D, "scan_results.csv"))
summary_overall       = pd.read_csv(os.path.join(D, "summary_overall.csv"))
summary_family        = pd.read_csv(os.path.join(D, "summary_by_attack_family.csv"))
summary_encoder       = pd.read_csv(os.path.join(D, "summary_by_encoder.csv"))
summary_placeholder   = pd.read_csv(os.path.join(D, "summary_by_placeholder.csv"))
heatmap               = pd.read_csv(os.path.join(D, "encoder_x_placeholder_heatmap.csv"))
predictions           = pd.read_csv(os.path.join(D, "predictions.csv"))
classification_report = pd.read_csv(os.path.join(D, "classification_report.csv"))
confusion_matrix      = pd.read_csv(os.path.join(D, "confusion_matrix.csv"))
model_summary         = pd.read_csv(os.path.join(D, "model_summary.csv"))
model_comparison      = pd.read_csv(os.path.join(D, "model_comparison.csv"))
reliability_bins      = pd.read_csv(os.path.join(D, "reliability_bins.csv"))


checks = []
def chk(name, ok, detail=""):
    status = "PASS" if ok else "FAIL"
    checks.append((name, ok, detail))
    print(f"  [{status}] {name}{(' — ' + detail) if detail else ''}")

print("\n=== A. Row-count alignment ===")
# scan_results = source minus unresolved
expected = len(src) - src_unres
chk("scan_results.csv row count = source minus unresolved",
    len(scan_results) == expected,
    f"expected {expected}, got {len(scan_results)}")

# summary_overall must say total = blocked + bypassed
total = int(summary_overall.loc[summary_overall.metric == "total_test_cases", "value"].iloc[0])
blk   = int(summary_overall.loc[summary_overall.metric == "blocked", "value"].iloc[0])
byp   = int(summary_overall.loc[summary_overall.metric == "bypassed", "value"].iloc[0])
chk("summary_overall: total = blocked + bypassed", total == blk + byp,
    f"{total} == {blk} + {byp}")
chk("summary_overall: total matches scan_results rows", total == len(scan_results),
    f"{total} vs {len(scan_results)}")
chk("summary_overall: blocked matches source blocked",  blk == src_blocked,
    f"{blk} vs {src_blocked}")
chk("summary_overall: bypassed matches source passed", byp == src_passed,
    f"{byp} vs {src_passed}")

print("\n=== B. Aggregations sum back to total ===")
for label, dfagg in [
    ("summary_by_attack_family", summary_family),
    ("summary_by_encoder",       summary_encoder),
    ("summary_by_placeholder",   summary_placeholder),
]:
    s_total = int(dfagg["total"].sum())
    s_blk   = int(dfagg["blocked"].sum())
    s_byp   = int(dfagg["bypassed"].sum())
    chk(f"{label}: total sums to {total}", s_total == total,
        f"got {s_total}")
    chk(f"{label}: blocked sums to {blk}", s_blk == blk,
        f"got {s_blk}")
    chk(f"{label}: bypassed sums to {byp}", s_byp == byp,
        f"got {s_byp}")

# heatmap totals
hm_total = int(heatmap["total"].sum())
hm_blk   = int(heatmap["blocked"].sum())
hm_byp   = int(heatmap["bypassed"].sum())
chk(f"heatmap: total sums to {total}", hm_total == total)
chk(f"heatmap: blocked sums to {blk}", hm_blk == blk)
chk(f"heatmap: bypassed sums to {byp}", hm_byp == byp)

print("\n=== C. Per-row alignment between scan_results and predictions ===")
chk("predictions row count = scan_results row count",
    len(predictions) == len(scan_results))
# Key columns should match position-by-position
for col in ["Encoder", "Placeholder", "Set", "Case", "is_bypass", "is_blocked"]:
    same = (scan_results[col].astype(str).values ==
            predictions[col].astype(str).values).all()
    chk(f"predictions.{col} matches scan_results.{col} in order", same)

print("\n=== D. Confusion matrix sums to dataset size ===")
cm_sum = int(confusion_matrix.iloc[:, 1:].values.sum())
chk(f"confusion_matrix total = {total}", cm_sum == total, f"got {cm_sum}")
# Confusion-matrix row sums should equal blocked / bypassed counts
row0_sum = int(confusion_matrix.iloc[0, 1:].sum())
row1_sum = int(confusion_matrix.iloc[1, 1:].sum())
chk(f"confusion_matrix row0 sum = blocked ({blk})", row0_sum == blk)
chk(f"confusion_matrix row1 sum = bypassed ({byp})", row1_sum == byp)

# Predictions should reproduce confusion matrix
pred_cm = predictions.groupby(["is_bypass", "predicted_label"]).size().unstack(fill_value=0)
expected_tn = pred_cm.loc[0, 0]; expected_fp = pred_cm.loc[0, 1]
expected_fn = pred_cm.loc[1, 0]; expected_tp = pred_cm.loc[1, 1]
cm = confusion_matrix.iloc[:, 1:].values
chk("CM[0,0] (TN) reproducible from predictions", cm[0,0] == expected_tn,
    f"{cm[0,0]} vs {expected_tn}")
chk("CM[0,1] (FP) reproducible from predictions", cm[0,1] == expected_fp,
    f"{cm[0,1]} vs {expected_fp}")
chk("CM[1,0] (FN) reproducible from predictions", cm[1,0] == expected_fn,
    f"{cm[1,0]} vs {expected_fn}")
chk("CM[1,1] (TP) reproducible from predictions", cm[1,1] == expected_tp,
    f"{cm[1,1]} vs {expected_tp}")

print("\n=== E. Classification report metrics reconcile from confusion matrix ===")
TN, FP = cm[0,0], cm[0,1]
FN, TP = cm[1,0], cm[1,1]
prec_blocked   = TN / (TN + FN) if (TN + FN) else 0
recall_blocked = TN / (TN + FP) if (TN + FP) else 0
f1_blocked     = 2 * prec_blocked * recall_blocked / (prec_blocked + recall_blocked) if (prec_blocked+recall_blocked) else 0

prec_bypass   = TP / (TP + FP) if (TP + FP) else 0
recall_bypass = TP / (TP + FN) if (TP + FN) else 0
f1_bypass     = 2 * prec_bypass * recall_bypass / (prec_bypass + recall_bypass) if (prec_bypass+recall_bypass) else 0

cr = classification_report.set_index("class")
def near(a, b, tol=0.001):
    try:
        return abs(float(a) - float(b)) < tol
    except: return False

chk("blocked.precision matches CM-derived",
    near(cr.loc["blocked", "precision"], prec_blocked),
    f"reported {cr.loc['blocked','precision']}, computed {prec_blocked:.4f}")
chk("blocked.recall matches CM-derived",
    near(cr.loc["blocked", "recall"], recall_blocked),
    f"reported {cr.loc['blocked','recall']}, computed {recall_blocked:.4f}")
chk("blocked.f1 matches CM-derived",
    near(cr.loc["blocked", "f1"], f1_blocked),
    f"reported {cr.loc['blocked','f1']}, computed {f1_blocked:.4f}")
chk("bypassed.precision matches CM-derived",
    near(cr.loc["bypassed", "precision"], prec_bypass),
    f"reported {cr.loc['bypassed','precision']}, computed {prec_bypass:.4f}")
chk("bypassed.recall matches CM-derived",
    near(cr.loc["bypassed", "recall"], recall_bypass),
    f"reported {cr.loc['bypassed','recall']}, computed {recall_bypass:.4f}")
chk("bypassed.f1 matches CM-derived",
    near(cr.loc["bypassed", "f1"], f1_bypass),
    f"reported {cr.loc['bypassed','f1']}, computed {f1_bypass:.4f}")

# support
chk("blocked.support equals blocked count",
    int(cr.loc["blocked", "support"]) == blk)
chk("bypassed.support equals bypassed count",
    int(cr.loc["bypassed", "support"]) == byp)

print("\n=== F. Reliability bins consistency ===")
rb_total = int(reliability_bins["count"].sum())
chk(f"reliability_bins counts sum to {total}", rb_total == total,
    f"got {rb_total}")
# bin probs should be in [0, 1]
all_in_range = ((reliability_bins["mean_predicted_prob"] >= 0) &
                (reliability_bins["mean_predicted_prob"] <= 1)).all()
chk("all mean predicted probs are in [0, 1]", bool(all_in_range))
all_emp_in_range = ((reliability_bins["empirical_bypass_rate"] >= 0) &
                    (reliability_bins["empirical_bypass_rate"] <= 1)).all()
chk("all empirical bypass rates are in [0, 1]", bool(all_emp_in_range))

print("\n=== G. Model comparison sanity ===")
# Headline F1 in model_summary should match the deployed row in model_comparison
ms_f1 = float(model_summary.loc[model_summary.metric == "cv_f1", "value"].iloc[0])
mc_deployed_f1 = float(model_comparison.loc[
    model_comparison.model.str.contains("Stacking"), "cv_f1"].iloc[0])
chk("model_summary.cv_f1 = model_comparison.deployed.cv_f1",
    abs(ms_f1 - mc_deployed_f1) < 0.0001,
    f"{ms_f1} vs {mc_deployed_f1}")

# All F1s in model_comparison are sane (0..1)
all_f1_sane = ((model_comparison["cv_f1"] >= 0) &
               (model_comparison["cv_f1"] <= 1)).all()
chk("all model_comparison F1 values in [0, 1]", bool(all_f1_sane))

print("\n=== H. Predictions probabilities are valid ===")
chk("predicted_bypass_probability in [0, 1] for every row",
    bool(((predictions["predicted_bypass_probability"] >= 0) &
          (predictions["predicted_bypass_probability"] <= 1)).all()))
chk("predicted_label is 0 or 1",
    bool(predictions["predicted_label"].isin([0, 1]).all()))
# correct flag
chk("'correct' column equals (predicted_label == is_bypass)",
    bool((predictions["correct"] ==
          (predictions["predicted_label"] == predictions["is_bypass"]).astype(int)).all()))

# Final summary
print("\n" + "=" * 70)
n_pass = sum(1 for _, ok, _ in checks if ok)
n_fail = sum(1 for _, ok, _ in checks if not ok)
print(f"TOTAL CHECKS: {len(checks)}   PASS: {n_pass}   FAIL: {n_fail}")
print("=" * 70)
if n_fail:
    print("\nFAILED CHECKS:")
    for name, ok, detail in checks:
        if not ok:
            print(f"  - {name}: {detail}")
