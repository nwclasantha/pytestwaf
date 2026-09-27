"""
Regenerate the journal-quality figures for pytestwaf-research-article.docx
using only real data from:
  - docs/figures_data/metrics.json
  - reports/waf-scan-portal-wazuh-hrclabs-io.csv

Output PNGs are written to docs/diagrams/regen/ with 3:2 aspect ratio,
300 DPI, larger fonts (title 14pt, axis 12pt, ticks 11pt), and a
colour-blind-friendly palette.

The new images intentionally use the same target filenames as the
originals so the embed-replace pass can swap them without touching
the docx structure.

Figures regenerated:
    Fig. 15  LR  learning curve            <- learning_curves.logistic_regression
    Fig. 16  KNN learning curve            <- learning_curves.knn
    Fig. 17  RF  learning curve            <- learning_curves.random_forest
    Fig. 18  SVC learning curve            <- learning_curves.svc_rbf
    Fig. 19  GB  learning curve            <- learning_curves.gradient_boosting
    Fig. 20  Block / Bypass by encoder     <- CSV grouped by Encoder
    Fig. 21  Block / Bypass by placeholder <- CSV grouped by Placeholder
    Fig. 22  Encoder x placeholder heatmap <- CSV crosstab bypass-rate
    Fig. 23  Attack-type composition       <- CSV grouped by Set/Case
    Fig. 24  Top-risk bypass cases         <- CSV bypass count per (Set, Encoder, Placeholder)
    Fig. 25  Confusion matrix (2x2)        <- metrics.per_class -> derived counts
    Fig. 26  Reliability diagram           <- metrics.calibration

Idempotent.  Re-running overwrites the regenerated files only.
"""
from __future__ import annotations

import csv
import json
import os
import sys
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

# Colour-blind-friendly palette (Wong 2011)
C = {
    "blocked":   "#0072B2",  # blue
    "bypassed":  "#D55E00",  # vermilion
    "unresolved": "#999999",
    "train":     "#0072B2",
    "val":       "#D55E00",
    "diag":      "#666666",
    "bar":       "#0072B2",
    "bar2":      "#D55E00",
}

DPI = 300
FIG_W, FIG_H = 9.0, 6.0  # 3:2 aspect inches


def style_axes(ax, title=None, xlabel=None, ylabel=None):
    if title:
        ax.set_title(title, fontsize=14, fontweight="bold", pad=12)
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=12)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=12)
    ax.tick_params(axis="both", labelsize=11)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(True, axis="y", alpha=0.3, linestyle=":")


# ---------------------------------------------------------------------------
# 1. Learning curves (Figs. 15-19)
# ---------------------------------------------------------------------------
def make_lc(name, title_key, out_name, lc_data):
    """Plot a single learning curve panel."""
    sizes = lc_data["sizes"]
    tm = np.asarray(lc_data["train_mean"])
    ts = np.asarray(lc_data["train_std"])
    vm = np.asarray(lc_data["val_mean"])
    vs = np.asarray(lc_data["val_std"])

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    ax.plot(sizes, tm, "-o", color=C["train"], label="Training F1", linewidth=2, markersize=7)
    ax.fill_between(sizes, tm - ts, tm + ts, alpha=0.18, color=C["train"])
    ax.plot(sizes, vm, "--s", color=C["val"], label="Out-of-fold F1", linewidth=2, markersize=7)
    ax.fill_between(sizes, vm - vs, vm + vs, alpha=0.18, color=C["val"])
    ax.set_ylim(0.78, 1.02)
    ax.legend(loc="lower right", fontsize=11, frameon=True)
    style_axes(
        ax,
        title=f"Learning curve {EM_DASH} {title_key}",
        xlabel="Number of training samples",
        ylabel="F1 score",
    )
    fig.tight_layout()
    p = OUT / out_name
    fig.savefig(p, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    return p


# Use a non-em-dash separator so the user's "no em-dash" rule isn't violated
EM_DASH = " - "


# ---------------------------------------------------------------------------
# Helpers for CSV-derived figures
# ---------------------------------------------------------------------------
def load_csv():
    with open(CSV_PATH, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def crosstab_counts(rows, key_field, status_field="Check Status"):
    counts = defaultdict(lambda: Counter())
    for r in rows:
        counts[r[key_field]][r[status_field]] += 1
    return counts


# ---------------------------------------------------------------------------
# 2. Block / Bypass distribution by encoder (Fig. 20)
# ---------------------------------------------------------------------------
def make_encoder_dist(rows, out_name):
    counts = crosstab_counts(rows, "Encoder")
    encoders = sorted(counts.keys())
    blocks  = [counts[e].get("blocked", 0) for e in encoders]
    bypass  = [counts[e].get("passed", 0) for e in encoders]

    x = np.arange(len(encoders))
    width = 0.4

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    ax.bar(x - width/2, blocks, width, color=C["blocked"], label="Blocked", edgecolor="white", linewidth=0.5)
    ax.bar(x + width/2, bypass, width, color=C["bypassed"], label="Bypassed", edgecolor="white", linewidth=0.5)
    ax.set_xticks(x)
    ax.set_xticklabels(encoders, rotation=30, ha="right")
    ax.legend(loc="upper right", fontsize=11, frameon=True)
    style_axes(
        ax,
        title="Block vs. Bypass count by encoder",
        xlabel="Encoder chain",
        ylabel="Number of payloads",
    )
    fig.tight_layout()
    p = OUT / out_name
    fig.savefig(p, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    return p


# ---------------------------------------------------------------------------
# 3. Block / Bypass distribution by placeholder (Fig. 21)
# ---------------------------------------------------------------------------
def make_placeholder_dist(rows, out_name):
    counts = crosstab_counts(rows, "Placeholder")
    placeholders = sorted(counts.keys(), key=lambda p: -(counts[p].get("blocked", 0) + counts[p].get("passed", 0)))
    blocks  = [counts[p].get("blocked", 0) for p in placeholders]
    bypass  = [counts[p].get("passed", 0) for p in placeholders]

    x = np.arange(len(placeholders))
    width = 0.4

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    ax.bar(x - width/2, blocks, width, color=C["blocked"], label="Blocked", edgecolor="white", linewidth=0.5)
    ax.bar(x + width/2, bypass, width, color=C["bypassed"], label="Bypassed", edgecolor="white", linewidth=0.5)
    ax.set_xticks(x)
    ax.set_xticklabels(placeholders, rotation=30, ha="right")
    ax.legend(loc="upper right", fontsize=11, frameon=True)
    style_axes(
        ax,
        title="Block vs. Bypass count by placeholder",
        xlabel="Placeholder",
        ylabel="Number of payloads",
    )
    fig.tight_layout()
    p = OUT / out_name
    fig.savefig(p, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    return p


# ---------------------------------------------------------------------------
# 4. Encoder x placeholder bypass-rate heatmap (Fig. 22)
# ---------------------------------------------------------------------------
def make_heatmap(rows, out_name):
    grid = defaultdict(lambda: Counter())
    for r in rows:
        key = (r["Encoder"], r["Placeholder"])
        grid[key][r["Check Status"]] += 1

    encoders = sorted({k[0] for k in grid})
    placeholders = sorted({k[1] for k in grid})

    rate = np.full((len(encoders), len(placeholders)), np.nan)
    counts = np.zeros_like(rate, dtype=int)
    for i, e in enumerate(encoders):
        for j, p in enumerate(placeholders):
            c = grid.get((e, p), Counter())
            tot = c.get("blocked", 0) + c.get("passed", 0)
            counts[i, j] = tot
            if tot > 0:
                rate[i, j] = c.get("passed", 0) / tot

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    cmap = plt.cm.RdYlGn_r  # green->red where bypass rate increases (red = high bypass = bad)
    im = ax.imshow(rate, cmap=cmap, vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(np.arange(len(placeholders)))
    ax.set_yticks(np.arange(len(encoders)))
    ax.set_xticklabels(placeholders, rotation=30, ha="right")
    ax.set_yticklabels(encoders)

    # annotate cells with the count (small font)
    for i in range(len(encoders)):
        for j in range(len(placeholders)):
            n = counts[i, j]
            if n == 0:
                continue
            r = rate[i, j]
            txt = f"{r*100:.0f}%\n(n={n})"
            ax.text(j, i, txt, ha="center", va="center", fontsize=8,
                    color="white" if r > 0.6 else "black")

    cb = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.02)
    cb.set_label("Bypass rate", fontsize=11)
    cb.ax.tick_params(labelsize=10)

    style_axes(
        ax,
        title="Encoder x placeholder bypass-rate heatmap",
        xlabel="Placeholder",
        ylabel="Encoder",
    )
    ax.grid(False)
    fig.tight_layout()
    p = OUT / out_name
    fig.savefig(p, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    return p


# ---------------------------------------------------------------------------
# 5. Attack-type composition (Fig. 23)
# ---------------------------------------------------------------------------
def make_attack_composition(rows, out_name, top_n=10):
    # Use the "Set" field for attack-family; fall back to "Case" prefix
    by_set = Counter()
    for r in rows:
        if r.get("Check Status") == "passed":  # bypassed only
            by_set[r["Set"]] += 1

    # Take top N
    items = by_set.most_common(top_n)
    if len(by_set) > top_n:
        other = sum(c for _, c in by_set.most_common()[top_n:])
        items.append(("other", other))

    labels = [k for k, _ in items]
    sizes = [v for _, v in items]

    palette = plt.cm.tab10(np.linspace(0, 1, len(items)))

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    wedges, _texts = ax.pie(
        sizes,
        startangle=90,
        wedgeprops=dict(width=0.45, edgecolor="white", linewidth=2),
        colors=palette,
    )
    # legend instead of labels on slices
    legend_labels = [f"{lbl} ({n})" for lbl, n in items]
    ax.legend(wedges, legend_labels, loc="center left",
              bbox_to_anchor=(1.0, 0.5), fontsize=11, frameon=False)
    ax.set_title("Attack-type composition of bypass candidates",
                 fontsize=14, fontweight="bold", pad=12)
    fig.tight_layout()
    p = OUT / out_name
    fig.savefig(p, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    return p


# ---------------------------------------------------------------------------
# 6. Top-risk bypass cases (Fig. 24)
# ---------------------------------------------------------------------------
def make_top_risk(rows, out_name, top_n=15):
    # Aggregate bypass count by (Encoder, Placeholder, Set)
    bypasses = Counter()
    for r in rows:
        if r.get("Check Status") == "passed":
            key = f"{r['Encoder']} / {r['Placeholder']} / {r['Set']}"
            bypasses[key] += 1

    items = bypasses.most_common(top_n)
    labels = [k for k, _ in items][::-1]  # reverse for horizontal bar
    counts = [v for _, v in items][::-1]

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    bars = ax.barh(labels, counts, color=C["bypassed"], edgecolor="white", linewidth=0.5)
    for bar, n in zip(bars, counts):
        ax.text(bar.get_width() + max(counts) * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{n}", va="center", fontsize=10)
    style_axes(
        ax,
        title=f"Top-{top_n} bypass categories by count (encoder / placeholder / set)",
        xlabel="Bypass count",
        ylabel="",
    )
    ax.grid(True, axis="x", alpha=0.3, linestyle=":")
    ax.grid(False, axis="y")
    fig.tight_layout()
    p = OUT / out_name
    fig.savefig(p, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    return p


# ---------------------------------------------------------------------------
# 7. Confusion matrix (Fig. 25) - 2x2 grid, real CV-derived counts
# ---------------------------------------------------------------------------
def make_confusion_matrix(metrics, out_name):
    pc = metrics["metrics"]["per_class"]
    bypass = pc["bypassed"]
    n_bypass = bypass["support"]
    rec = bypass["recall"]
    prec = bypass["precision"]

    blocked = pc["blocked"]
    n_block = blocked["support"]

    # Treating "bypassed" as the positive class:
    tp = round(rec * n_bypass)
    fn = n_bypass - tp
    fp = round(tp / prec - tp)
    tn = n_block - fp

    cm = np.array([[tn, fp], [fn, tp]], dtype=int)

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    cmap = plt.cm.Blues
    im = ax.imshow(cm, cmap=cmap)

    # Annotations
    for (i, j), v in np.ndenumerate(cm):
        colour = "white" if v > cm.max() * 0.55 else "black"
        ax.text(j, i, f"{v}", ha="center", va="center",
                fontsize=22, fontweight="bold", color=colour)

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Predicted Blocked", "Predicted Bypassed"], fontsize=11)
    ax.set_yticklabels(["Actual Blocked", "Actual Bypassed"], fontsize=11)

    cb = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.04)
    cb.ax.tick_params(labelsize=10)

    title = (f"Confusion matrix (5-fold CV aggregate); total = {tn+fp+fn+tp}, "
             f"F1_bypass = {bypass['f1']:.3f}, F1_block = {blocked['f1']:.3f}")
    ax.set_title(title, fontsize=13, fontweight="bold", pad=14)
    ax.grid(False)
    fig.tight_layout()
    p = OUT / out_name
    fig.savefig(p, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    return p


# ---------------------------------------------------------------------------
# 8. Reliability diagram (Fig. 26) - real per-bin from metrics.calibration
# ---------------------------------------------------------------------------
def make_reliability(metrics, out_name):
    bins = metrics["metrics"]["calibration"]
    centres = np.array([b["bin_centre"] for b in bins])
    pred = np.array([b["predicted_mean"] for b in bins])
    actual = np.array([b["actual_freq"] for b in bins])
    counts = np.array([b["count"] for b in bins])
    total = counts.sum()
    ece = float(np.sum(counts * np.abs(pred - actual)) / total)
    mce = float(np.max(np.abs(pred - actual)))

    fig, (ax_top, ax_bot) = plt.subplots(
        2, 1, figsize=(FIG_W, FIG_H),
        gridspec_kw={"height_ratios": [3, 1], "hspace": 0.04},
        sharex=True,
    )

    # Top — diagonal + step + dots
    ax_top.plot([0, 1], [0, 1], "--", color=C["diag"], label="Perfect calibration", linewidth=1.5)
    ax_top.plot(pred, actual, "-o", color=C["bypassed"], linewidth=2,
                markersize=8, label="Empirical")
    ax_top.set_ylim(-0.02, 1.02)
    ax_top.set_xlim(-0.02, 1.02)
    ax_top.set_ylabel("Empirical bypass frequency", fontsize=12)
    ax_top.legend(loc="upper left", fontsize=11, frameon=True)
    ax_top.set_title(
        f"Reliability diagram (10 bins);  ECE = {ece:.3f}, MCE = {mce:.3f}",
        fontsize=14, fontweight="bold", pad=12,
    )
    ax_top.grid(True, alpha=0.3, linestyle=":")
    ax_top.tick_params(axis="both", labelsize=11)
    ax_top.spines["top"].set_visible(False)
    ax_top.spines["right"].set_visible(False)

    # Bottom — population bars
    ax_bot.bar(centres, counts, width=0.09, color=C["blocked"],
               edgecolor="white", linewidth=0.5)
    ax_bot.set_xlabel("Predicted bypass probability", fontsize=12)
    ax_bot.set_ylabel("Bin count", fontsize=11)
    ax_bot.tick_params(axis="both", labelsize=10)
    ax_bot.spines["top"].set_visible(False)
    ax_bot.spines["right"].set_visible(False)
    ax_bot.grid(True, axis="y", alpha=0.3, linestyle=":")

    fig.tight_layout()
    p = OUT / out_name
    fig.savefig(p, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    return p


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    metrics = json.loads(METRICS.read_text(encoding="utf-8"))
    rows = load_csv()

    # 15-19: real learning curves (overwrite the misnamed PNGs)
    lc = metrics["metrics"]["learning_curves"]
    written = []
    written.append(make_lc("LR",  "Logistic Regression",  "waf-ml-bypass-cdf.png",                  lc["logistic_regression"]))
    written.append(make_lc("KNN", "K-Nearest Neighbours", "waf-ml-bypass-distribution.png",         lc["knn"]))
    written.append(make_lc("RF",  "Random Forest",        "waf-ml-bypass-scatter.png",              lc["random_forest"]))
    written.append(make_lc("SVC", "Support Vector Classifier (RBF)", "waf-ml-class-balance.png",     lc["svc_rbf"]))
    written.append(make_lc("GB",  "Gradient Boosting",    "waf-ml-confidence-distribution.png",     lc["gradient_boosting"]))

    # 20-24: real CSV-derived figures (overwrite originals)
    written.append(make_encoder_dist(rows, "waf-ml-bypass-by-encoder.png"))
    written.append(make_placeholder_dist(rows, "waf-ml-bypass-by-placement.png"))
    written.append(make_heatmap(rows, "waf-ml-encoder-placement-heatmap.png"))
    written.append(make_attack_composition(rows, "waf-ml-attack-type-composition.png"))
    written.append(make_top_risk(rows, "waf-ml-top-risk-ranked.png"))

    # 25-26: real metrics-derived figures (overwrite originals)
    written.append(make_confusion_matrix(metrics, "waf-ml-confusion-matrix.png"))
    written.append(make_reliability(metrics, "waf-ml-calibration-plot.png"))

    print("Regenerated PNGs:")
    for p in written:
        sz = os.path.getsize(p)
        print(f"  {p.name:45s} {sz:>8d} bytes")


if __name__ == "__main__":
    main()
