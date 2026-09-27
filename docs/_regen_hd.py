"""
Re-render every regenerated figure at journal-grade HD quality:
  - 600 DPI (was 300)
  - Larger fonts: title 18pt, axis 16pt, tick 14pt, annotations 12pt
  - 10 x 6.67 inches at 600 DPI -> 6000 x 4000 px native
  - Helvetica/Arial sans-serif font family
  - Tight bounding box but no aggressive cropping
  - Anti-aliasing on
  - PNG with optimal compression / no resampling

Then update the docx so the inline display width is 6.5 inches (full
single-column on a typical 8.5x11 page) at the native 3:2 aspect, so
the image is rendered at ~924 PPI on screen and at the full source
resolution in print.
"""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

csv.field_size_limit(10_000_000)

ROOT = Path(__file__).resolve().parent
METRICS = ROOT / "figures_data" / "metrics.json"
CSV_PATH = ROOT.parent / "reports" / "waf-scan-portal-wazuh-hrclabs-io.csv"
OUT = ROOT / "diagrams"

# ----- Style ---------------------------------------------------------------
plt.rcParams.update({
    "font.family":     "DejaVu Sans",
    "font.size":       14,
    "axes.titlesize":  18,
    "axes.titleweight": "bold",
    "axes.labelsize":  16,
    "xtick.labelsize": 14,
    "ytick.labelsize": 14,
    "legend.fontsize": 14,
    "figure.dpi":      600,
    "savefig.dpi":     600,
    "savefig.bbox":    "tight",
    "savefig.pad_inches": 0.15,
    "axes.linewidth":  1.2,
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "axes.grid":       False,
    "grid.alpha":      0.3,
    "grid.linestyle":  ":",
    "lines.linewidth": 2.5,
    "lines.markersize": 9,
})

C_BLOCK    = "#0072B2"
C_BYPASS   = "#D55E00"
C_HIGHLIGHT = "#009E73"
C_DIAG     = "#666666"
C_GREY     = "#888888"

FW, FH = 10.0, 6.67   # 3:2 aspect, generous for HD


def style(ax, title=None, xlabel=None, ylabel=None):
    if title:
        ax.set_title(title, pad=14)
    if xlabel:
        ax.set_xlabel(xlabel)
    if ylabel:
        ax.set_ylabel(ylabel)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(True, axis="y", alpha=0.3, linestyle=":")


def save(fig, name):
    p = OUT / name
    fig.savefig(p, dpi=600, bbox_inches="tight", pad_inches=0.18)
    plt.close(fig)
    return p


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def load_csv():
    return list(csv.DictReader(open(CSV_PATH, encoding="utf-8")))


# ---------------------------------------------------------------------------
# Fig 13 - per-category block / bypass
# ---------------------------------------------------------------------------
def fig13(rows):
    by_set = defaultdict(lambda: Counter())
    for r in rows:
        by_set[r["Set"]][r["Check Status"]] += 1

    sets = sorted(by_set.keys(),
                  key=lambda s: -(by_set[s].get("blocked", 0) + by_set[s].get("passed", 0)))
    blocks = [by_set[s].get("blocked", 0) for s in sets]
    bypass = [by_set[s].get("passed",  0) for s in sets]

    y = np.arange(len(sets))
    h = 0.4
    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.barh(y - h / 2, blocks, h, color=C_BLOCK,  label="Blocked",  edgecolor="white", linewidth=0.8)
    ax.barh(y + h / 2, bypass, h, color=C_BYPASS, label="Bypassed", edgecolor="white", linewidth=0.8)
    ax.set_yticks(y); ax.set_yticklabels(sets); ax.invert_yaxis()
    ax.legend(loc="lower right", frameon=True)
    style(ax,
          title="Hybrid ML predictions on the production WAF target",
          xlabel="Number of payloads", ylabel="Test set")
    ax.grid(True, axis="x", alpha=0.3, linestyle=":")
    ax.grid(False, axis="y")
    return save(fig, "waf-attack-prevention.png")


# ---------------------------------------------------------------------------
# Fig 14 - 8-model F1 comparison with error bars
# ---------------------------------------------------------------------------
def fig14(metrics):
    abl = metrics["metrics"]["ablation"]
    label_map = {
        "logistic_regression": "Logistic Regression",
        "knn": "K-Nearest Neighbours",
        "svc_rbf": "SVC (RBF)",
        "random_forest": "Random Forest",
        "mlp": "Multi-Layer Perceptron",
        "gradient_boosting": "Gradient Boosting",
        "stacking_uncalibrated": "Stacking (raw)",
        "stacking_calibrated_isotonic": "Stacking + isotonic (deployed)",
    }
    models = []
    for k, n in label_map.items():
        if k in abl:
            v = abl[k]
            models.append((n, v["f1_mean"], v.get("f1_std") or 0.0,
                           k == "stacking_calibrated_isotonic"))
    models.sort(key=lambda m: m[1])

    names  = [m[0] for m in models]
    f1s    = [m[1] for m in models]
    stds   = [m[2] for m in models]
    cols   = [C_HIGHLIGHT if m[3] else C_BLOCK for m in models]

    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.barh(names, f1s, xerr=stds, color=cols, edgecolor="white", linewidth=0.8,
            error_kw=dict(ecolor=C_GREY, capsize=5, lw=1.8))
    for i, (n, f, s) in enumerate(zip(names, f1s, stds)):
        ann = f"{f:.4f}" + (f"  ±{s:.4f}" if s > 0 else "")
        ax.text(f + 0.001, i, ann, va="center", fontsize=12)
    ax.set_xlim(0.83, 1.0)
    style(ax,
          title="Hybrid supervised ML models comparison (5-fold CV F1)",
          xlabel="F1 score (mean ± std across 5 folds)", ylabel="")
    ax.grid(True, axis="x", alpha=0.3, linestyle=":")
    ax.grid(False, axis="y")
    from matplotlib.patches import Patch
    ax.legend(handles=[
        Patch(facecolor=C_HIGHLIGHT, label="Deployed (calibrated)"),
        Patch(facecolor=C_BLOCK,     label="Baseline / raw"),
    ], loc="lower right", frameon=True)
    return save(fig, "waf-accuracy-breakdown.png")


# ---------------------------------------------------------------------------
# Fig 15-19 - learning curves
# ---------------------------------------------------------------------------
def lc(name_full, key, lc_data, out):
    sizes = lc_data["sizes"]
    tm = np.asarray(lc_data["train_mean"]); ts = np.asarray(lc_data["train_std"])
    vm = np.asarray(lc_data["val_mean"]);   vs = np.asarray(lc_data["val_std"])

    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.plot(sizes, tm, "-o", color=C_BLOCK, label="Training F1")
    ax.fill_between(sizes, tm - ts, tm + ts, alpha=0.2, color=C_BLOCK)
    ax.plot(sizes, vm, "--s", color=C_BYPASS, label="Out-of-fold F1")
    ax.fill_between(sizes, vm - vs, vm + vs, alpha=0.2, color=C_BYPASS)
    ax.set_ylim(0.78, 1.02)
    ax.legend(loc="lower right", frameon=True)
    style(ax,
          title=f"Learning curve - {name_full}",
          xlabel="Number of training samples", ylabel="F1 score")
    return save(fig, out)


# ---------------------------------------------------------------------------
# Fig 20-21 - block / bypass by encoder / placeholder
# ---------------------------------------------------------------------------
def by_field(rows, field, out, axis_label):
    counts = defaultdict(lambda: Counter())
    for r in rows: counts[r[field]][r["Check Status"]] += 1
    keys = sorted(counts.keys())
    blocks = [counts[k].get("blocked", 0) for k in keys]
    bypass = [counts[k].get("passed",  0) for k in keys]

    x = np.arange(len(keys)); w = 0.4
    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.bar(x - w / 2, blocks, w, color=C_BLOCK,  label="Blocked",  edgecolor="white", linewidth=0.8)
    ax.bar(x + w / 2, bypass, w, color=C_BYPASS, label="Bypassed", edgecolor="white", linewidth=0.8)
    ax.set_xticks(x); ax.set_xticklabels(keys, rotation=30, ha="right")
    ax.legend(loc="upper right", frameon=True)
    style(ax,
          title=f"Block vs. Bypass count by {axis_label.lower()}",
          xlabel=axis_label.capitalize(), ylabel="Number of payloads")
    return save(fig, out)


# ---------------------------------------------------------------------------
# Fig 22 - encoder x placeholder heatmap
# ---------------------------------------------------------------------------
def heatmap(rows):
    grid = defaultdict(lambda: Counter())
    for r in rows:
        grid[(r["Encoder"], r["Placeholder"])][r["Check Status"]] += 1
    encs = sorted({k[0] for k in grid})
    pls  = sorted({k[1] for k in grid})

    rate = np.full((len(encs), len(pls)), np.nan)
    cnt  = np.zeros_like(rate, dtype=int)
    for i, e in enumerate(encs):
        for j, p in enumerate(pls):
            c = grid.get((e, p), Counter())
            t = c.get("blocked", 0) + c.get("passed", 0)
            cnt[i, j] = t
            if t > 0: rate[i, j] = c.get("passed", 0) / t

    fig, ax = plt.subplots(figsize=(FW, FH))
    im = ax.imshow(rate, cmap=plt.cm.RdYlGn_r, vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(np.arange(len(pls))); ax.set_xticklabels(pls, rotation=30, ha="right")
    ax.set_yticks(np.arange(len(encs))); ax.set_yticklabels(encs)
    for i in range(len(encs)):
        for j in range(len(pls)):
            n = cnt[i, j]
            if n == 0: continue
            r = rate[i, j]
            ax.text(j, i, f"{int(round(r*100))}%\n(n={n})",
                    ha="center", va="center", fontsize=10,
                    color="white" if r > 0.6 else "black", fontweight="bold")
    cb = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.02)
    cb.set_label("Bypass rate"); cb.ax.tick_params(labelsize=12)
    style(ax,
          title="Encoder x placeholder bypass-rate heatmap",
          xlabel="Placeholder", ylabel="Encoder")
    ax.grid(False)
    return save(fig, "waf-ml-encoder-placement-heatmap.png")


# ---------------------------------------------------------------------------
# Fig 23 - attack-type composition
# ---------------------------------------------------------------------------
def comp(rows, top_n=10):
    by_set = Counter()
    for r in rows:
        if r.get("Check Status") == "passed":
            by_set[r["Set"]] += 1
    items = by_set.most_common(top_n)
    if len(by_set) > top_n:
        items.append(("other", sum(c for _, c in by_set.most_common()[top_n:])))
    sizes = [v for _, v in items]
    palette = plt.cm.tab10(np.linspace(0, 1, len(items)))
    fig, ax = plt.subplots(figsize=(FW, FH))
    wedges, _ = ax.pie(sizes, startangle=90,
                       wedgeprops=dict(width=0.45, edgecolor="white", linewidth=2.5),
                       colors=palette)
    legend = [f"{lbl}  ({n})" for lbl, n in items]
    ax.legend(wedges, legend, loc="center left", bbox_to_anchor=(1.02, 0.5),
              fontsize=14, frameon=False)
    ax.set_title("Attack-type composition of bypass candidates", pad=14)
    return save(fig, "waf-ml-attack-type-composition.png")


# ---------------------------------------------------------------------------
# Fig 24 - top-15 bypass categories
# ---------------------------------------------------------------------------
def top_risk(rows, top_n=15):
    bypasses = Counter()
    for r in rows:
        if r.get("Check Status") == "passed":
            bypasses[f"{r['Encoder']} / {r['Placeholder']} / {r['Set']}"] += 1
    items = bypasses.most_common(top_n)[::-1]
    labels = [k for k, _ in items]
    counts = [v for _, v in items]

    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.barh(labels, counts, color=C_BYPASS, edgecolor="white", linewidth=0.8)
    for i, n in enumerate(counts):
        ax.text(n + max(counts) * 0.01, i, f"{n}", va="center", fontsize=12)
    style(ax,
          title=f"Top-{top_n} bypass categories (encoder / placeholder / set)",
          xlabel="Bypass count", ylabel="")
    ax.grid(True, axis="x", alpha=0.3, linestyle=":")
    ax.grid(False, axis="y")
    return save(fig, "waf-ml-top-risk-ranked.png")


# ---------------------------------------------------------------------------
# Fig 25 - confusion matrix
# ---------------------------------------------------------------------------
def cm(metrics):
    pc = metrics["metrics"]["per_class"]
    bp = pc["bypassed"]; bk = pc["blocked"]
    n_b = bp["support"]; tp = round(bp["recall"] * n_b)
    fn = n_b - tp; fp = round(tp / bp["precision"] - tp); tn = bk["support"] - fp
    M = np.array([[tn, fp], [fn, tp]], dtype=int)

    fig, ax = plt.subplots(figsize=(FW, FH))
    im = ax.imshow(M, cmap=plt.cm.Blues)
    for (i, j), v in np.ndenumerate(M):
        ax.text(j, i, f"{v}", ha="center", va="center",
                fontsize=44, fontweight="bold",
                color="white" if v > M.max() * 0.55 else "black")
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["Predicted Blocked", "Predicted Bypassed"])
    ax.set_yticklabels(["Actual Blocked", "Actual Bypassed"])
    cb = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.04); cb.ax.tick_params(labelsize=12)
    title = (f"Confusion matrix (5-fold CV aggregate); total = {tn+fp+fn+tp}, "
             f"F1_bypass = {bp['f1']:.3f}, F1_block = {bk['f1']:.3f}")
    ax.set_title(title, pad=14, fontsize=15)
    ax.grid(False)
    return save(fig, "waf-ml-confusion-matrix.png")


# ---------------------------------------------------------------------------
# Fig 26 - reliability diagram
# ---------------------------------------------------------------------------
def reliability(metrics):
    bins = metrics["metrics"]["calibration"]
    centres = np.array([b["bin_centre"] for b in bins])
    pred = np.array([b["predicted_mean"] for b in bins])
    actual = np.array([b["actual_freq"] for b in bins])
    counts = np.array([b["count"] for b in bins])
    total = counts.sum()
    ece = float(np.sum(counts * np.abs(pred - actual)) / total)
    mce = float(np.max(np.abs(pred - actual)))

    fig, (a, b) = plt.subplots(2, 1, figsize=(FW, FH),
                               gridspec_kw={"height_ratios": [3, 1], "hspace": 0.05},
                               sharex=True)
    a.plot([0, 1], [0, 1], "--", color=C_DIAG, label="Perfect calibration", linewidth=2)
    a.plot(pred, actual, "-o", color=C_BYPASS, linewidth=2.5, markersize=10, label="Empirical")
    a.set_ylim(-0.02, 1.02); a.set_xlim(-0.02, 1.02)
    a.set_ylabel("Empirical bypass frequency")
    a.legend(loc="upper left", frameon=True)
    a.set_title(f"Reliability diagram (10 bins);  ECE = {ece:.3f}, MCE = {mce:.3f}", pad=14)
    a.grid(True, alpha=0.3, linestyle=":")
    a.spines["top"].set_visible(False); a.spines["right"].set_visible(False)

    b.bar(centres, counts, width=0.09, color=C_BLOCK, edgecolor="white", linewidth=0.8)
    b.set_xlabel("Predicted bypass probability")
    b.set_ylabel("Bin count")
    b.spines["top"].set_visible(False); b.spines["right"].set_visible(False)
    b.grid(True, axis="y", alpha=0.3, linestyle=":")

    return save(fig, "waf-ml-calibration-plot.png")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    metrics = json.loads(METRICS.read_text(encoding="utf-8"))
    rows = load_csv()
    written = []
    written.append(fig13(rows))
    written.append(fig14(metrics))
    L = metrics["metrics"]["learning_curves"]
    written.append(lc("Logistic Regression",                  "lr",   L["logistic_regression"], "waf-ml-bypass-cdf.png"))
    written.append(lc("K-Nearest Neighbours",                 "knn",  L["knn"],                  "waf-ml-bypass-distribution.png"))
    written.append(lc("Random Forest",                        "rf",   L["random_forest"],        "waf-ml-bypass-scatter.png"))
    written.append(lc("Support Vector Classifier (RBF)",      "svc",  L["svc_rbf"],              "waf-ml-class-balance.png"))
    written.append(lc("Gradient Boosting",                    "gb",   L["gradient_boosting"],    "waf-ml-confidence-distribution.png"))
    written.append(by_field(rows, "Encoder",     "waf-ml-bypass-by-encoder.png",     "encoder chain"))
    written.append(by_field(rows, "Placeholder", "waf-ml-bypass-by-placement.png",   "placeholder"))
    written.append(heatmap(rows))
    written.append(comp(rows))
    written.append(top_risk(rows))
    written.append(cm(metrics))
    written.append(reliability(metrics))

    print("Regenerated HD figures (600 DPI):")
    for p in written:
        from PIL import Image
        img = Image.open(p)
        sz = p.stat().st_size
        print(f"  {p.name:45s}  {img.size[0]:5d}x{img.size[1]:<5d}  {sz/1024:6.1f} KB")


if __name__ == "__main__":
    main()
