"""Generate result-section figures (Fig 7-13) for the research article.

Reads verified numbers from the scan's metrics JSON
(docs/figures_data/metrics.json, copied from
reports/<report>_metrics.json after the scan).

If the JSON file is missing, raises an error rather than silently producing
fabricated charts.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = Path(__file__).parent / "figures"
OUT.mkdir(exist_ok=True)
DATA_PATH = Path(__file__).parent / "figures_data" / "metrics.json"

# Publication style
plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans"],
    "font.size": 11,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.color": "#dddddd",
    "grid.linewidth": 0.6,
    "axes.edgecolor": "#333333",
    "xtick.color": "#333333",
    "ytick.color": "#333333",
    "legend.frameon": False,
    "savefig.dpi": 200,
    "savefig.bbox": "tight",
    "figure.facecolor": "white",
    "axes.facecolor": "white",
})

PALETTE = {
    "random_forest":               "#222222",
    "gradient_boosting":           "#444444",
    "mlp":                         "#666666",
    "logistic_regression":         "#1a1a1a",
    "knn":                         "#555555",
    "svc_rbf":                     "#333333",
    "stacking_uncalibrated":       "#000000",
    "stacking_calibrated_isotonic": "#000000",
}

LABEL = {
    "random_forest":               "Random Forest",
    "gradient_boosting":           "Gradient Boosting",
    "mlp":                         "MLP",
    "logistic_regression":         "Logistic Regression",
    "knn":                         "KNN",
    "svc_rbf":                     "SVC (RBF)",
    "stacking_uncalibrated":       "Stacking (raw)",
    "stacking_calibrated_isotonic": "Stacking + Isotonic",
}


def load_metrics() -> dict:
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"{DATA_PATH} not found. Copy reports/*_metrics.json there first."
        )
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))


def fig7_predictions(scan: dict):
    """Single-target prediction outcome for the evaluated WAF."""
    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    blocked = scan["blocked"]
    bypassed = scan["bypassed"]
    total = blocked + bypassed
    bars = ax.bar(["Blocked", "Bypassed"],
                  [blocked, bypassed],
                  color=["#888888", "#222222"],
                  edgecolor=["#555555", "#000000"], width=0.55)
    for b, v in zip(bars, [blocked, bypassed]):
        ax.text(b.get_x() + b.get_width()/2, v + 10, f"{v}\n({100*v/total:.1f}%)",
                ha="center", fontsize=11, weight="bold")
    ax.set_ylabel("Test cases (N = {} payloads)".format(total))
    title = "Hybrid ML predictions on production WAF target"
    ax.set_title(title, fontsize=13, weight="bold", pad=12)
    ax.set_ylim(0, max(blocked, bypassed) * 1.25)
    fig.savefig(OUT / "fig07_predictions.png")
    plt.close(fig)


def fig8_model_comparison(ablation: dict):
    """Per-model F1 comparison (precision/recall/F1)."""
    fig, ax = plt.subplots(figsize=(9.5, 5.0))
    order = ["random_forest", "gradient_boosting", "mlp",
             "logistic_regression", "knn", "svc_rbf",
             "stacking_uncalibrated", "stacking_calibrated_isotonic"]
    order = [m for m in order if m in ablation]

    f1s   = [ablation[m].get("f1_mean", 0) for m in order]
    pres  = [ablation[m].get("precision_mean", 0) for m in order]
    recs  = [ablation[m].get("recall_mean", 0) for m in order]

    x = np.arange(len(order))
    w = 0.27
    ax.bar(x - w, pres, w, label="Precision",
           color="#cccccc", edgecolor="#000000", hatch="")
    ax.bar(x,     recs, w, label="Recall",
           color="#888888", edgecolor="#000000", hatch="//")
    ax.bar(x + w, f1s,  w, label="F1",
           color="#222222", edgecolor="#000000", hatch="")
    ax.set_xticks(x)
    ax.set_xticklabels([LABEL[m] for m in order], rotation=20, ha="right", fontsize=9)
    lo = max(0.5, min(min(pres), min(recs), min(f1s)) - 0.05) if pres and recs else 0.5
    ax.set_ylim(lo, 1.0)
    ax.set_ylabel("Score (5-fold stratified CV)")
    ax.set_title("Hybrid supervised ML models comparison · scan #22 production target",
                 fontsize=13, weight="bold", pad=12)
    ax.legend(loc="lower left", ncol=3)
    # Annotate F1
    for i, v in enumerate(f1s):
        ax.text(i + w, v + 0.005, f"{v:.3f}", ha="center", fontsize=8, color="#000000")
    # Highlight deployed model
    if "stacking_calibrated_isotonic" in order:
        idx = order.index("stacking_calibrated_isotonic")
        ax.axvspan(idx - 0.45, idx + 0.45, alpha=0.08, color="#000000")
    fig.savefig(OUT / "fig08_model_comparison.png")
    plt.close(fig)


def _learning_curve_plot(model_key: str, lc: dict, out_name: str):
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    sizes = np.array(lc["sizes"])
    train_mean = np.array(lc["train_mean"])
    train_std  = np.array(lc["train_std"])
    val_mean   = np.array(lc["val_mean"])
    val_std    = np.array(lc["val_std"])

    color = PALETTE.get(model_key, "#444444")
    ax.plot(sizes, train_mean, "o-", color=color, label="Training F1", linewidth=2)
    ax.fill_between(sizes, train_mean - train_std, train_mean + train_std,
                    alpha=0.18, color=color)
    ax.plot(sizes, val_mean, "s--", color=color, alpha=0.7,
            label="CV F1", linewidth=1.6)
    ax.fill_between(sizes, val_mean - val_std, val_mean + val_std,
                    alpha=0.10, color=color)

    ax.set_xlabel("Training samples")
    ax.set_ylabel("F1 score")
    ymin = max(0.5, min(val_mean.min(), train_mean.min()) - 0.05)
    ax.set_ylim(ymin, 1.0)
    ax.legend(loc="lower right", fontsize=9)
    ax.set_title(f"{LABEL[model_key]} · learning curve · scan #22 data",
                 fontsize=12, weight="bold", pad=10)
    fig.savefig(OUT / out_name)
    plt.close(fig)


def all_figures():
    data = load_metrics()
    scan = data["scan"]
    metrics = data["metrics"]
    ablation = metrics.get("ablation", {})
    learning_curves = metrics.get("learning_curves", {})

    fig7_predictions(scan)
    fig8_model_comparison(ablation)

    # Fig 9-13 → 5 selected models (LR, KNN, RF, SVC, GB to mirror template)
    mapping = [
        ("logistic_regression",  "fig09_lr_learning_curve.png"),
        ("knn",                  "fig10_knn_learning_curve.png"),
        ("random_forest",        "fig11_rf_learning_curve.png"),
        ("svc_rbf",              "fig12_svc_learning_curve.png"),
        ("gradient_boosting",    "fig13_gb_learning_curve.png"),
    ]
    for key, fname in mapping:
        if key in learning_curves:
            _learning_curve_plot(key, learning_curves[key], fname)
            print(f"  wrote {fname}")
        else:
            print(f"  SKIP {fname} (no learning curve data for {key})")

    print(f"\nWrote figures to {OUT}/")
    print(f"Source data: {DATA_PATH}")


if __name__ == "__main__":
    all_figures()
