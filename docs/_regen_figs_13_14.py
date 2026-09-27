"""
Regenerate Figs. 13 and 14 with real data so they match the manuscript text.

Fig. 13 — Hybrid ML predictions on the production WAF target.
    The body text says "per-category block and bypass counts".  We render
    a grouped horizontal bar chart by `Set` (attack family) showing the
    blocked vs. bypassed counts per category.

Fig. 14 — Hybrid supervised ML models comparison.
    The body text enumerates 8 baseline F1 scores with std-dev.  We render
    a bar chart of those 8 baselines with error bars, sorted descending,
    and highlight the deployed calibrated stacking ensemble.
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

C_BLOCK = "#0072B2"
C_BYPASS = "#D55E00"
C_HIGHLIGHT = "#009E73"  # green for the deployed model
C_GREY = "#888888"

DPI = 300
FIG_W, FIG_H = 9.0, 6.0


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


# ---------------------------------------------------------------------------
# Fig. 13 — per-category block / bypass
# ---------------------------------------------------------------------------
def make_fig13():
    rows = list(csv.DictReader(open(CSV_PATH, encoding="utf-8")))
    by_set = defaultdict(lambda: Counter())
    for r in rows:
        by_set[r["Set"]][r["Check Status"]] += 1

    sets = sorted(by_set.keys(),
                  key=lambda s: -(by_set[s].get("blocked", 0) + by_set[s].get("passed", 0)))
    blocks = [by_set[s].get("blocked", 0) for s in sets]
    bypass = [by_set[s].get("passed",  0) for s in sets]

    y = np.arange(len(sets))
    h = 0.4

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    ax.barh(y - h / 2, blocks, h, color=C_BLOCK,  label="Blocked",  edgecolor="white", linewidth=0.5)
    ax.barh(y + h / 2, bypass, h, color=C_BYPASS, label="Bypassed", edgecolor="white", linewidth=0.5)
    ax.set_yticks(y)
    ax.set_yticklabels(sets)
    ax.invert_yaxis()
    ax.legend(loc="lower right", fontsize=11, frameon=True)
    style_axes(
        ax,
        title="Hybrid ML predictions on the production WAF target (per-category counts)",
        xlabel="Number of payloads",
        ylabel="Test set",
    )
    ax.grid(True, axis="x", alpha=0.3, linestyle=":")

    fig.tight_layout()
    p = OUT / "waf-attack-prevention.png"
    fig.savefig(p, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {p.name}")
    return p


# ---------------------------------------------------------------------------
# Fig. 14 — 8-model F1 comparison with error bars
# ---------------------------------------------------------------------------
def make_fig14():
    metrics = json.loads(METRICS.read_text(encoding="utf-8"))
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
    for key, name in label_map.items():
        if key not in abl:
            continue
        v = abl[key]
        models.append({
            "name":  name,
            "key":   key,
            "f1":    v["f1_mean"],
            "std":   v.get("f1_std") or 0.0,
            "deployed": (key == "stacking_calibrated_isotonic"),
        })

    # Sort ascending by F1 for horizontal bar
    models.sort(key=lambda m: m["f1"])

    names  = [m["name"] for m in models]
    f1s    = [m["f1"]   for m in models]
    stds   = [m["std"]  for m in models]
    colors = [C_HIGHLIGHT if m["deployed"] else C_BLOCK for m in models]

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    ax.barh(
        names, f1s,
        xerr=stds,
        color=colors,
        edgecolor="white",
        linewidth=0.5,
        error_kw=dict(ecolor=C_GREY, capsize=4, lw=1.5),
    )
    for n, f, s in zip(names, f1s, stds):
        annotation = f"{f:.4f}" + (f" ± {s:.4f}" if s > 0 else "")
        ax.text(f + 0.0006, names.index(n), annotation, va="center", fontsize=10)

    ax.set_xlim(0.83, 1.0)
    style_axes(
        ax,
        title="Hybrid supervised ML models comparison (5-fold cross-validated F1)",
        xlabel="F1 score (mean ± std across 5 folds)",
        ylabel="",
    )
    ax.grid(True, axis="x", alpha=0.3, linestyle=":")

    # Legend marker for the highlighted bar
    from matplotlib.patches import Patch
    legend_elems = [
        Patch(facecolor=C_HIGHLIGHT, label="Deployed (calibrated)"),
        Patch(facecolor=C_BLOCK,     label="Baseline / raw"),
    ]
    ax.legend(handles=legend_elems, loc="lower right", fontsize=11, frameon=True)

    fig.tight_layout()
    p = OUT / "waf-accuracy-breakdown.png"
    fig.savefig(p, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {p.name}")
    return p


def main():
    make_fig13()
    make_fig14()
    print("Done.")


if __name__ == "__main__":
    main()
