"""
Re-render every regenerated figure so the text inside displays at journal-
quality 9-11pt when the figure is shown at 3.30" wide in the docx.

Math:
  source-font 14pt at source-width 10in -> at display 3.30in shows ~4.6pt  (too small)
  source-font 11pt at source-width  4in -> at display 3.30in shows ~9.1pt  (correct)

So we render at 4 x 2.67 inches (3:2 aspect) at 600 DPI:
  - 2400 x 1600 px native -> 727 PPI when displayed at 3.30 in (HD)
  - 11pt source / 4.0 source-in * 3.30 display-in = 9.07pt visible

Idempotent.  Backup created on first run.
"""
from __future__ import annotations

import csv
import json
import shutil
from collections import Counter, defaultdict
from io import BytesIO
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from PIL import Image

csv.field_size_limit(10_000_000)

ROOT = Path(__file__).resolve().parent
METRICS = ROOT / "figures_data" / "metrics.json"
CSV_PATH = ROOT.parent / "reports" / "waf-scan-portal-wazuh-hrclabs-io.csv"
DIAG = ROOT / "diagrams"

# Smaller render dimensions so that text scales correctly at 3.30" display
plt.rcParams.update({
    "font.family":     "DejaVu Sans",
    "font.size":       10,
    "axes.titlesize":  12,
    "axes.titleweight": "bold",
    "axes.labelsize":  11,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "figure.dpi":      600,
    "savefig.dpi":     600,
    "lines.linewidth": 1.6,
    "lines.markersize": 6,
})

C_BLOCK   = "#0072B2"
C_BYPASS  = "#D55E00"
C_GREEN   = "#009E73"
C_GREY    = "#888888"
C_DIAG    = "#666666"

FW, FH = 4.0, 2.67  # 3:2 at smaller scale


def style(ax, title=None, xlabel=None, ylabel=None):
    if title:
        ax.set_title(title, pad=10)
    if xlabel:
        ax.set_xlabel(xlabel)
    if ylabel:
        ax.set_ylabel(ylabel)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def save(fig, name):
    p = DIAG / name
    fig.savefig(p, dpi=600, bbox_inches="tight", pad_inches=0.10)
    plt.close(fig)
    return p


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
    y = np.arange(len(sets)); h = 0.4
    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.barh(y - h / 2, blocks, h, color=C_BLOCK,  label="Blocked",  edgecolor="white", linewidth=0.5)
    ax.barh(y + h / 2, bypass, h, color=C_BYPASS, label="Bypassed", edgecolor="white", linewidth=0.5)
    ax.set_yticks(y); ax.set_yticklabels(sets); ax.invert_yaxis()
    ax.legend(loc="lower right", frameon=True)
    style(ax, title="Hybrid ML predictions on production WAF",
          xlabel="Number of payloads", ylabel="Test set")
    ax.grid(True, axis="x", alpha=0.3, linestyle=":")
    return save(fig, "waf-attack-prevention.png")


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
    names = [m[0] for m in models]; f1s = [m[1] for m in models]
    stds = [m[2] for m in models]; cols = [C_GREEN if m[3] else C_BLOCK for m in models]
    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.barh(names, f1s, xerr=stds, color=cols, edgecolor="white", linewidth=0.5,
            error_kw=dict(ecolor=C_GREY, capsize=3, lw=1))
    for i, (n, f, s) in enumerate(zip(names, f1s, stds)):
        ann = f"{f:.4f}" + (f" ±{s:.3f}" if s > 0 else "")
        ax.text(f + 0.001, i, ann, va="center", fontsize=8)
    ax.set_xlim(0.83, 1.0)
    style(ax, title="Hybrid supervised ML models comparison",
          xlabel="F1 (mean ± std, 5-fold CV)", ylabel="")
    ax.grid(True, axis="x", alpha=0.3, linestyle=":")
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(facecolor=C_GREEN, label="Deployed"),
                       Patch(facecolor=C_BLOCK, label="Baseline")],
              loc="lower right", frameon=True, fontsize=8)
    return save(fig, "waf-accuracy-breakdown.png")


def lc(name, key, lc_data, out):
    sizes = lc_data["sizes"]
    tm = np.asarray(lc_data["train_mean"]); ts = np.asarray(lc_data["train_std"])
    vm = np.asarray(lc_data["val_mean"]); vs = np.asarray(lc_data["val_std"])
    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.plot(sizes, tm, "-o", color=C_BLOCK, label="Training F1")
    ax.fill_between(sizes, tm - ts, tm + ts, alpha=0.2, color=C_BLOCK)
    ax.plot(sizes, vm, "--s", color=C_BYPASS, label="Out-of-fold F1")
    ax.fill_between(sizes, vm - vs, vm + vs, alpha=0.2, color=C_BYPASS)
    ax.set_ylim(0.78, 1.02)
    ax.legend(loc="lower right", frameon=True, fontsize=8)
    style(ax, title=f"Learning curve - {name}",
          xlabel="Training samples", ylabel="F1 score")
    ax.grid(True, alpha=0.3, linestyle=":")
    return save(fig, out)


def by_field(rows, field, out, axis_label):
    counts = defaultdict(lambda: Counter())
    for r in rows: counts[r[field]][r["Check Status"]] += 1
    keys = sorted(counts.keys())
    blocks = [counts[k].get("blocked", 0) for k in keys]
    bypass = [counts[k].get("passed",  0) for k in keys]
    x = np.arange(len(keys)); w = 0.4
    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.bar(x - w / 2, blocks, w, color=C_BLOCK,  label="Blocked",  edgecolor="white", linewidth=0.5)
    ax.bar(x + w / 2, bypass, w, color=C_BYPASS, label="Bypassed", edgecolor="white", linewidth=0.5)
    ax.set_xticks(x); ax.set_xticklabels(keys, rotation=35, ha="right", fontsize=8)
    ax.legend(loc="upper right", frameon=True, fontsize=8)
    style(ax, title=f"Block vs. Bypass by {axis_label.lower()}",
          xlabel=axis_label.capitalize(), ylabel="Number of payloads")
    ax.grid(True, axis="y", alpha=0.3, linestyle=":")
    return save(fig, out)


def heatmap(rows):
    grid = defaultdict(lambda: Counter())
    for r in rows:
        grid[(r["Encoder"], r["Placeholder"])][r["Check Status"]] += 1
    encs = sorted({k[0] for k in grid}); pls = sorted({k[1] for k in grid})
    rate = np.full((len(encs), len(pls)), np.nan)
    cnt = np.zeros_like(rate, dtype=int)
    for i, e in enumerate(encs):
        for j, p in enumerate(pls):
            c = grid.get((e, p), Counter())
            t = c.get("blocked", 0) + c.get("passed", 0)
            cnt[i, j] = t
            if t > 0: rate[i, j] = c.get("passed", 0) / t
    fig, ax = plt.subplots(figsize=(FW, FH))
    im = ax.imshow(rate, cmap=plt.cm.RdYlGn_r, vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(np.arange(len(pls))); ax.set_xticklabels(pls, rotation=35, ha="right", fontsize=7)
    ax.set_yticks(np.arange(len(encs))); ax.set_yticklabels(encs, fontsize=8)
    for i in range(len(encs)):
        for j in range(len(pls)):
            n = cnt[i, j]
            if n == 0: continue
            r = rate[i, j]
            ax.text(j, i, f"{int(round(r*100))}%", ha="center", va="center", fontsize=6,
                    color="white" if r > 0.6 else "black", fontweight="bold")
    cb = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.02)
    cb.set_label("Bypass rate", fontsize=9); cb.ax.tick_params(labelsize=8)
    style(ax, title="Encoder x placeholder bypass-rate heatmap",
          xlabel="Placeholder", ylabel="Encoder")
    ax.grid(False)
    return save(fig, "waf-ml-encoder-placement-heatmap.png")


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
                       wedgeprops=dict(width=0.45, edgecolor="white", linewidth=1.5),
                       colors=palette)
    legend = [f"{lbl} ({n})" for lbl, n in items]
    ax.legend(wedges, legend, loc="center left", bbox_to_anchor=(1.02, 0.5),
              fontsize=9, frameon=False)
    ax.set_title("Attack-type composition of bypass candidates", pad=10, fontsize=12, fontweight="bold")
    return save(fig, "waf-ml-attack-type-composition.png")


def top_risk(rows, top_n=15):
    bypasses = Counter()
    for r in rows:
        if r.get("Check Status") == "passed":
            bypasses[f"{r['Encoder']}/{r['Placeholder']}/{r['Set']}"] += 1
    items = bypasses.most_common(top_n)[::-1]
    labels = [k for k, _ in items]; counts = [v for _, v in items]
    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.barh(labels, counts, color=C_BYPASS, edgecolor="white", linewidth=0.5)
    for i, n in enumerate(counts):
        ax.text(n + max(counts) * 0.01, i, f"{n}", va="center", fontsize=8)
    style(ax, title=f"Top-{top_n} bypass categories",
          xlabel="Bypass count", ylabel="")
    ax.tick_params(axis="y", labelsize=7)
    ax.grid(True, axis="x", alpha=0.3, linestyle=":")
    return save(fig, "waf-ml-top-risk-ranked.png")


def cm(metrics):
    pc = metrics["metrics"]["per_class"]
    bp = pc["bypassed"]; bk = pc["blocked"]
    n_b = bp["support"]; tp = round(bp["recall"] * n_b)
    fn = n_b - tp; fp = round(tp / bp["precision"] - tp); tn = bk["support"] - fp
    M = np.array([[tn, fp], [fn, tp]], dtype=int)
    fig, ax = plt.subplots(figsize=(FW, FH))
    im = ax.imshow(M, cmap=plt.cm.Blues)
    for (i, j), v in np.ndenumerate(M):
        ax.text(j, i, f"{v}", ha="center", va="center", fontsize=24, fontweight="bold",
                color="white" if v > M.max() * 0.55 else "black")
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["Predicted Blocked", "Predicted Bypassed"], fontsize=9)
    ax.set_yticklabels(["Actual Blocked", "Actual Bypassed"], fontsize=9)
    cb = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.04); cb.ax.tick_params(labelsize=8)
    ax.set_title(f"Confusion matrix (5-fold CV); F1_bypass={bp['f1']:.3f}, F1_block={bk['f1']:.3f}",
                 fontsize=10, fontweight="bold", pad=8)
    ax.grid(False)
    return save(fig, "waf-ml-confusion-matrix.png")


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
    a.plot([0, 1], [0, 1], "--", color=C_DIAG, label="Perfect", linewidth=1.2)
    a.plot(pred, actual, "-o", color=C_BYPASS, linewidth=1.6, markersize=6, label="Empirical")
    a.set_ylim(-0.02, 1.02); a.set_xlim(-0.02, 1.02)
    a.set_ylabel("Empirical bypass freq.", fontsize=10)
    a.legend(loc="upper left", frameon=True, fontsize=9)
    a.set_title(f"Reliability diagram; ECE={ece:.3f}, MCE={mce:.3f}", pad=8, fontsize=11, fontweight="bold")
    a.grid(True, alpha=0.3, linestyle=":")
    a.spines["top"].set_visible(False); a.spines["right"].set_visible(False)
    b.bar(centres, counts, width=0.09, color=C_BLOCK, edgecolor="white", linewidth=0.5)
    b.set_xlabel("Predicted bypass probability", fontsize=10)
    b.set_ylabel("Bin count", fontsize=9)
    b.spines["top"].set_visible(False); b.spines["right"].set_visible(False)
    b.grid(True, axis="y", alpha=0.3, linestyle=":")
    return save(fig, "waf-ml-calibration-plot.png")


def fig27(rows):
    KEYWORDS = [("XSS","xss"),("SQL injection","sql"),("Command injection","shell"),
                ("Command injection","rce"),("Command injection","command"),
                ("Path traversal/LFI","lfi"),("Path traversal/LFI","traversal"),
                ("LDAP injection","ldap"),("XML/XXE","xxe"),("XML/XXE","xml"),
                ("NoSQL injection","nosql"),("CRLF injection","crlf"),
                ("Mail injection","mail"),("Template injection","template"),
                ("Template injection","ssti"),("Template injection","ssi")]
    counts = defaultdict(lambda: Counter())
    for r in rows:
        case = r["Case"].lower()
        family = None
        for fam, kw in KEYWORDS:
            if kw in case: family = fam; break
        if family is None: family = "Other/mixed"
        counts[family][r["Check Status"]] += 1
    families = sorted(counts.keys(),
                      key=lambda f: -(counts[f].get("blocked", 0) + counts[f].get("passed", 0)))
    blocks = [counts[f].get("blocked", 0) for f in families]
    bypass = [counts[f].get("passed", 0) for f in families]
    y = np.arange(len(families)); h = 0.4
    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.barh(y - h / 2, blocks, h, color=C_BLOCK,  label="Blocked",  edgecolor="white", linewidth=0.5)
    ax.barh(y + h / 2, bypass, h, color=C_BYPASS, label="Bypassed", edgecolor="white", linewidth=0.5)
    ax.set_yticks(y); ax.set_yticklabels(families, fontsize=8); ax.invert_yaxis()
    ax.legend(loc="lower right", frameon=True, fontsize=8)
    style(ax, title="Block vs. bypass by attack family",
          xlabel="Number of payloads", ylabel="Attack family")
    ax.grid(True, axis="x", alpha=0.3, linestyle=":")
    return save(fig, "waf-mitre-attack.png")


def fig28(metrics):
    fi = metrics["metrics"]["feature_importance"]
    items = sorted(fi.items(), key=lambda x: x[1], reverse=True)[:15][::-1]
    names = [k for k, _ in items]; values = [v for _, v in items]
    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.barh(names, values, color=C_BLOCK, edgecolor="white", linewidth=0.5)
    for i, v in enumerate(values):
        ax.text(v + max(values) * 0.005, i, f"{v:.3f}", va="center", fontsize=8)
    style(ax, title="Top-15 feature importances",
          xlabel="Importance (RF gini decrease)", ylabel="")
    ax.tick_params(axis="y", labelsize=8)
    ax.grid(True, axis="x", alpha=0.3, linestyle=":")
    return save(fig, "waf-kill-chain.png")


def fig29(metrics):
    pc = metrics["metrics"]["per_class"]
    classes = ["blocked", "bypassed"]
    metrics_list = ["precision", "recall", "f1"]
    vals = np.array([[pc[c][m] for m in metrics_list] for c in classes])
    x = np.arange(len(metrics_list)); w = 0.35
    fig, ax = plt.subplots(figsize=(FW, FH))
    bars1 = ax.bar(x - w / 2, vals[0], w, color=C_BLOCK,  label=f"Blocked (n={pc['blocked']['support']})",
                   edgecolor="white", linewidth=0.5)
    bars2 = ax.bar(x + w / 2, vals[1], w, color=C_BYPASS, label=f"Bypassed (n={pc['bypassed']['support']})",
                   edgecolor="white", linewidth=0.5)
    for bars in (bars1, bars2):
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.005,
                    f"{b.get_height():.3f}", ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x); ax.set_xticklabels([m.capitalize() for m in metrics_list])
    ax.set_ylim(0.8, 1.02)
    ax.legend(loc="lower right", frameon=True, fontsize=8)
    style(ax, title="Per-class precision/recall/F1",
          xlabel="Metric", ylabel="Score")
    ax.grid(True, axis="y", alpha=0.3, linestyle=":")
    return save(fig, "waf-tactic-radar.png")


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
    written.append(lc("Logistic Regression",                  "lr",  L["logistic_regression"], "waf-ml-bypass-cdf.png"))
    written.append(lc("K-Nearest Neighbours",                 "knn", L["knn"],                  "waf-ml-bypass-distribution.png"))
    written.append(lc("Random Forest",                        "rf",  L["random_forest"],        "waf-ml-bypass-scatter.png"))
    written.append(lc("Support Vector Classifier (RBF)",      "svc", L["svc_rbf"],              "waf-ml-class-balance.png"))
    written.append(lc("Gradient Boosting",                    "gb",  L["gradient_boosting"],    "waf-ml-confidence-distribution.png"))
    written.append(by_field(rows, "Encoder",     "waf-ml-bypass-by-encoder.png",     "encoder chain"))
    written.append(by_field(rows, "Placeholder", "waf-ml-bypass-by-placement.png",   "placeholder"))
    written.append(heatmap(rows))
    written.append(comp(rows))
    written.append(top_risk(rows))
    written.append(cm(metrics))
    written.append(reliability(metrics))
    written.append(fig27(rows))
    written.append(fig28(metrics))
    written.append(fig29(metrics))

    # Flatten alpha for all
    for p in written:
        img = Image.open(p)
        if img.mode == "RGBA":
            bg = Image.new("RGB", img.size, (255, 255, 255))
            bg.paste(img, mask=img.split()[3])
            bg.save(p, format="PNG", optimize=False, compress_level=1, dpi=(600, 600))
        else:
            img.convert("RGB").save(p, format="PNG", optimize=False, compress_level=1, dpi=(600, 600))

    print("Re-rendered HD figures (sized for 3.30in display, 9-11pt visible fonts):")
    for p in written:
        img = Image.open(p)
        sz = p.stat().st_size
        print(f"  {p.name:45s}  {img.size[0]:5d}x{img.size[1]:<5d}  {sz/1024:6.1f} KB")


if __name__ == "__main__":
    main()
