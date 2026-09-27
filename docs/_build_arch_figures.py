"""Generate IEEE-style colored block diagrams for the 12 architecture
figures (Fig 1-6 + 14-19). Colors and layout match the template
(JCM-20514-v5-fixed.docx) which uses light pastel fills with black
borders and bold text.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUT = Path(__file__).parent / "figures"
OUT.mkdir(exist_ok=True)

# Publication style — large fonts, white background
plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans"],
    "font.size": 12,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
    "savefig.facecolor": "white",
    "figure.facecolor": "white",
    "axes.facecolor": "white",
})

# Template-matching pastel palette (light fills + dark borders)
C_GREEN  = "#d4edda"   # entry points
C_BLUE   = "#d6e5f5"   # processing stages
C_YELLOW = "#fff3cd"   # decisions
C_PINK   = "#f8d7da"   # outputs / blocked
C_PURPLE = "#e5d4f1"   # ML / intelligence
C_ORANGE = "#fde2c4"   # warnings / mutations
C_GRAY   = "#e9ecef"   # neutral
BORDER   = "#000000"
TEXT     = "#000000"


def _box(ax, xy, w, h, text, fill=C_BLUE, fontsize=11, weight="normal"):
    x, y = xy
    box = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.03,rounding_size=0.06",
        linewidth=1.4, edgecolor=BORDER, facecolor=fill,
    )
    ax.add_patch(box)
    ax.text(x + w/2, y + h/2, text,
            ha="center", va="center",
            fontsize=fontsize, weight=weight, color=TEXT)


def _arrow(ax, x1, y1, x2, y2, label=None, label_offset=(0, 0.05)):
    arr = FancyArrowPatch((x1, y1), (x2, y2),
                          arrowstyle="-|>", mutation_scale=14,
                          color=BORDER, linewidth=1.1)
    ax.add_patch(arr)
    if label:
        mx = (x1 + x2) / 2 + label_offset[0]
        my = (y1 + y2) / 2 + label_offset[1]
        ax.text(mx, my, label, ha="center", va="center",
                fontsize=10, color=TEXT, style="italic",
                bbox=dict(facecolor="white", edgecolor="none", pad=1))


def _setup(ax, xlim, ylim):
    ax.set_xlim(xlim)
    ax.set_ylim(ylim)
    ax.set_aspect("equal")
    ax.axis("off")


# ── Fig 1: Algorithm of proposed (10-stage closed-loop pipeline) ───────────
def fig01_algorithm():
    fig, ax = plt.subplots(figsize=(8.0, 5.0))
    _setup(ax, (-0.5, 17), (-0.5, 9.5))
    stages = [
        ("CLI\nInvocation",         0.5, 6.5, C_GREEN),
        ("Pre-Flight",              3.4, 6.5, C_BLUE),
        ("Corpus\nExpansion",       6.3, 6.5, C_BLUE),
        ("Scanning\n(1110 cases)",  9.2, 6.5, C_BLUE),
        ("4-layer\nClassification", 12.1, 6.5, C_YELLOW),
        ("ML\nLearning",            15.0, 6.5, C_PURPLE),
        ("Adaptive\nMutation",      15.0, 3.0, C_ORANGE),
        ("Autofix\n+ IaC",           9.2, 3.0, C_BLUE),
        ("HTML / 3D\nReport",        6.3, 3.0, C_BLUE),
        ("Cross-Scan\nPersistence",  3.4, 3.0, C_GREEN),
    ]
    for txt, x, y, c in stages:
        _box(ax, (x, y), 2.0, 1.7, txt, fill=c, fontsize=11, weight="bold")
    # Top row arrows
    for i in range(5):
        _arrow(ax, stages[i][1] + 2.0, stages[i][2] + 0.85,
               stages[i+1][1], stages[i+1][2] + 0.85)
    # Down to mutation
    _arrow(ax, stages[5][1] + 1.0, stages[5][2],
           stages[6][1] + 1.0, stages[6][2] + 1.7)
    # Bottom row arrows (right to left)
    for i in range(6, 9):
        _arrow(ax, stages[i][1], stages[i][2] + 0.85,
               stages[i+1][1] + 2.0, stages[i+1][2] + 0.85)
    # Loop-back: persistence -> pre-flight (warm start)
    _arrow(ax, stages[9][1] + 1.0, stages[9][2] + 1.7,
           stages[1][1] + 1.0, stages[1][2],
           label="warm-start", label_offset=(0, 0.1))

    fig.savefig(OUT / "fig01_algorithm.png")
    plt.close(fig)


# ── Fig 2: Component architecture (5 packages + dependencies) ──────────────
def fig02_components():
    fig, ax = plt.subplots(figsize=(7.0, 5.5))
    _setup(ax, (-0.3, 14), (-0.3, 11))
    # Top: cli/main.py orchestrator
    _box(ax, (4.5, 9.0), 5.0, 1.4,
         "cli/main.py · Typer Orchestration Layer",
         fill=C_GREEN, fontsize=12, weight="bold")
    # Middle row: 4 packages
    pkgs = [(0.5, 6.0, "scanner/", C_BLUE),
            (3.7, 6.0, "ml/", C_PURPLE),
            (6.9, 6.0, "report/", C_PINK),
            (10.1, 6.0, "helpers/", C_YELLOW)]
    for x, y, n, c in pkgs:
        _box(ax, (x, y), 2.7, 1.6, n, fill=c, fontsize=12, weight="bold")
        _arrow(ax, 7.0, 9.0, x + 1.35, y + 1.6)
    # Bottom row: outputs
    outs = [(0.5, 2.5, "./reports/\nHTML · IaC · JSON",  C_GRAY),
            (5.5, 2.5, "~/.gotestwaf/models/\nengine.joblib",  C_GRAY),
            (10.5, 2.5, "stdout / Slack /\nTeams / SMTP",  C_GRAY)]
    for x, y, n, c in outs:
        _box(ax, (x, y), 3.0, 1.5, n, fill=c, fontsize=10)
    _arrow(ax, 1.85, 6.0, 2.0, 4.0)
    _arrow(ax, 5.05, 6.0, 7.0, 4.0)
    _arrow(ax, 8.25, 6.0, 12.0, 4.0)
    fig.savefig(OUT / "fig02_components.png")
    plt.close(fig)


# ── Fig 3: 4-layer response classification pipeline ────────────────────────
def fig03_classification():
    fig, ax = plt.subplots(figsize=(7.5, 8.0))
    _setup(ax, (-0.3, 16), (-0.3, 16))
    nodes = [
        ("HTTP response",                           4.5, 14.5, C_GRAY),
        ("Layer 1 · WAF detector regex",            4.5, 12.3, C_BLUE),
        ("Layer 2 · Baseline Jaccard + WAF kwds",   4.5, 10.0, C_BLUE),
        ("Layer 2.5 · Response autoencoder",        4.5,  7.7, C_BLUE),
        ("Layer 3 · Online clustering",             4.5,  5.4, C_BLUE),
        ("UNRESOLVED → post-scan ML",               4.5,  3.0, C_YELLOW),
    ]
    out_nodes = [
        ("BLOCKED",                              12.0, 12.3, C_PINK),
        ("BLOCKED",                              12.0, 10.0, C_PINK),
        ("PASSED",                                14.0, 10.0, C_GREEN),
        ("BLOCKED · anomaly",                    12.0,  7.7, C_PINK),
        ("BLOCKED",                              12.0,  5.4, C_PINK),
    ]
    for txt, x, y, c in nodes:
        _box(ax, (x - 3.0, y - 0.7), 6.0, 1.4, txt, fill=c, fontsize=12, weight="bold")
    for txt, x, y, c in out_nodes:
        _box(ax, (x - 1.6, y - 0.6), 3.2, 1.2, txt, fill=c, fontsize=11, weight="bold")

    for i in range(len(nodes) - 1):
        _arrow(ax, 4.5, nodes[i][2] - 0.7, 4.5, nodes[i+1][2] + 0.7, label="no", label_offset=(0.4, 0))
    for i in range(1, 5):
        _arrow(ax, nodes[i][1] + 3.0, nodes[i][2],
               out_nodes[i-1][1] - 1.6, out_nodes[i-1][2],
               label="yes", label_offset=(0, 0.2))
    fig.savefig(OUT / "fig03_classification.png")
    plt.close(fig)


# ── Fig 4: Deployment topology ─────────────────────────────────────────────
def fig04_deployment():
    fig, ax = plt.subplots(figsize=(7.0, 6.0))
    _setup(ax, (-0.3, 14), (-0.3, 12))
    for i, txt in enumerate(["CLI", "Cron", "CI / CD"]):
        _box(ax, (1.0 + 4.5*i, 10.0), 3.0, 1.2, txt,
             fill=C_GREEN, fontsize=12, weight="bold")
    _box(ax, (1.5, 7.5), 11.0, 1.4,
         "Docker Engine (host: Linux / Windows / macOS)",
         fill=C_GRAY, fontsize=12, weight="bold")
    _box(ax, (3.0, 5.0), 8.0, 1.6,
         "pytestwaf:r17 image\n(Python 3.13 + sklearn 1.8 + httpx + jinja2)",
         fill=C_BLUE, fontsize=11)
    _box(ax, (3.0, 2.4), 8.0, 1.6,
         "gotestwaf process · async pool + stacking ensemble in-memory",
         fill=C_PURPLE, fontsize=11, weight="bold")
    _box(ax, (-0.2, 2.4), 2.7, 1.6,
         "Volume mounts:\nURLs.txt :ro\nreports/ :rw\nmodels/ :rw",
         fill=C_YELLOW, fontsize=9)
    _box(ax, (11.5, 2.4), 2.5, 1.6,
         "HTTPS\negress →\ntarget WAF",
         fill=C_PINK, fontsize=10, weight="bold")
    for i in range(3):
        _arrow(ax, 2.5 + 4.5*i, 10.0, 7.0, 8.9)
    _arrow(ax, 7.0, 7.5, 7.0, 6.6)
    _arrow(ax, 7.0, 5.0, 7.0, 4.0)
    _arrow(ax, 2.5, 3.2, 3.0, 3.2)
    _arrow(ax, 11.0, 3.2, 11.5, 3.2)
    fig.savefig(OUT / "fig04_deployment.png")
    plt.close(fig)


# ── Fig 5: ML Training architecture ────────────────────────────────────────
def fig05_training():
    fig, ax = plt.subplots(figsize=(7.5, 6.0))
    _setup(ax, (-0.3, 16), (-0.3, 12))
    _box(ax, (0.5, 9.0), 3.5, 1.6,
         "Payload +\nResponse",
         fill=C_GRAY, fontsize=11, weight="bold")
    _box(ax, (0.5, 6.5), 3.5, 1.6,
         "Outcome\n(0 / 1 label)",
         fill=C_GRAY, fontsize=11, weight="bold")
    _box(ax, (5.0, 7.7), 3.5, 1.8,
         "Feature\nextraction\n(30 dims)",
         fill=C_BLUE, fontsize=11)
    _box(ax, (9.5, 7.7), 4.0, 1.8,
         "compute_\nsample_weight\n(balanced)",
         fill=C_YELLOW, fontsize=11)
    base_y = 5.0
    _box(ax, (0.5, base_y), 3.5, 1.5,
         "RandomForest\nn=200, d=6",
         fill=C_PURPLE, fontsize=10, weight="bold")
    _box(ax, (4.5, base_y), 3.5, 1.5,
         "GradientBoost\nn=120, d=4",
         fill=C_PURPLE, fontsize=10, weight="bold")
    _box(ax, (8.5, base_y), 3.5, 1.5,
         "MLP\nhidden (48,24)",
         fill=C_PURPLE, fontsize=10, weight="bold")
    _box(ax, (4.5, 2.5), 7.0, 1.5,
         "Stacking · LogReg meta + Isotonic calibration",
         fill=C_ORANGE, fontsize=11, weight="bold")
    _box(ax, (4.5, 0.3), 7.0, 1.4,
         "Calibrated bypass-probability ensemble",
         fill=C_GREEN, fontsize=11, weight="bold")
    _arrow(ax, 4.0, 9.8, 5.0, 8.6)
    _arrow(ax, 8.5, 8.6, 9.5, 8.6)
    _arrow(ax, 4.0, 7.3, 9.5, 8.0)
    for x in (2.25, 6.25, 10.25):
        _arrow(ax, x, 7.7, x, 6.5)
    for x in (2.25, 6.25, 10.25):
        _arrow(ax, x, 5.0, 8.0, 4.0)
    _arrow(ax, 8.0, 2.5, 8.0, 1.7)
    fig.savefig(OUT / "fig05_training.png")
    plt.close(fig)


# ── Fig 6: Inference / Prediction modes ────────────────────────────────────
def fig06_prediction():
    fig, ax = plt.subplots(figsize=(7.5, 6.0))
    _setup(ax, (-0.3, 16), (-0.3, 12))
    _box(ax, (0.5, 10.4), 7.0, 1.0,
         "Fast Mode (warm-start)",
         fill=C_GREEN, fontsize=12, weight="bold")
    _box(ax, (8.5, 10.4), 7.0, 1.0,
         "Adaptive Round (post-scan)",
         fill=C_ORANGE, fontsize=12, weight="bold")
    fast_steps = ["Load saved model from\n~/.gotestwaf/models/<waf>/",
                  "Score upcoming\npayload queue",
                  "Reorder by\nbypass probability",
                  "Drop below\nthreshold"]
    for i, t in enumerate(fast_steps):
        _box(ax, (0.5, 8.0 - 1.7*i), 7.0, 1.4, t, fill=C_BLUE, fontsize=10)
    adapt_steps = ["Bypassed combos\n(encoder × placeholder)",
                   "generate_ai_payloads\n(700 mutations)",
                   "Score each, sort ↓",
                   "Fire top-K via\nml_worker"]
    for i, t in enumerate(adapt_steps):
        _box(ax, (8.5, 8.0 - 1.7*i), 7.0, 1.4, t, fill=C_PURPLE, fontsize=10)
    for col_x in (4.0, 12.0):
        for i in range(3):
            y_top = 8.0 - 1.7*i
            y_bot = 8.0 - 1.7*(i+1) + 1.4
            _arrow(ax, col_x, y_top, col_x, y_bot)
    fig.savefig(OUT / "fig06_prediction.png")
    plt.close(fig)


# ── Fig 14: Adaptive mutation engine (5-stage cycle) ───────────────────────
def fig14_mutation():
    fig, ax = plt.subplots(figsize=(7.5, 5.5))
    _setup(ax, (-0.3, 16), (-0.3, 12))
    _box(ax, (5.5, 5.0), 5.0, 2.2,
         "700 ML mutations\nper cycle",
         fill=C_ORANGE, fontsize=12, weight="bold")
    stages = [
        ("Stage 1\nPost-scan telemetry",     8.0, 10.0, C_GREEN),
        ("Stage 2\nPattern extraction",     13.0, 6.0,  C_BLUE),
        ("Stage 3\nPayload generation",     11.5, 1.5,  C_PURPLE),
        ("Stage 4\nML scoring",              4.5, 1.5,  C_PURPLE),
        ("Stage 5\nTargeted firing",         3.0, 6.0,  C_PINK),
    ]
    for txt, x, y, c in stages:
        _box(ax, (x - 1.6, y - 0.7), 3.2, 1.4, txt, fill=c, fontsize=10, weight="bold")
    for i in range(5):
        x1, y1 = stages[i][1], stages[i][2]
        x2, y2 = stages[(i+1) % 5][1], stages[(i+1) % 5][2]
        _arrow(ax, x1, y1, x2, y2)
    fig.savefig(OUT / "fig14_mutation.png")
    plt.close(fig)


# ── Fig 15: Cross-scan persistence ─────────────────────────────────────────
def fig15_persistence():
    fig, ax = plt.subplots(figsize=(7.5, 5.0))
    _setup(ax, (-0.3, 16), (-0.3, 9))
    _box(ax, (0.5, 6.5), 3.5, 1.6, "Scan #N\noutput", fill=C_BLUE, fontsize=11, weight="bold")
    _box(ax, (0.5, 1.5), 3.5, 1.6, "Trained\nmodels", fill=C_PURPLE, fontsize=11, weight="bold")
    _box(ax, (5.5, 3.5), 4.5, 2.5,
         "~/.gotestwaf/models/\n<waf>/\nengine.joblib +\nknowledge.json",
         fill=C_YELLOW, fontsize=10, weight="bold")
    _box(ax, (11.5, 3.5), 3.5, 2.5,
         "Scan #N+1\nwarm-start",
         fill=C_GREEN, fontsize=11, weight="bold")
    _arrow(ax, 4.0, 7.3, 5.5, 5.5)
    _arrow(ax, 4.0, 2.3, 5.5, 4.0)
    _arrow(ax, 10.0, 4.7, 11.5, 4.7, label="primes", label_offset=(0, 0.3))
    fig.savefig(OUT / "fig15_persistence.png")
    plt.close(fig)


# ── Fig 16: Multi-cloud autofix + IaC pipeline ─────────────────────────────
def fig16_autofix():
    fig, ax = plt.subplots(figsize=(7.5, 5.0))
    _setup(ax, (-0.3, 16), (-0.3, 9))
    _box(ax, (0.0, 5.0), 3.5, 1.6, "Bypassed\ncategories", fill=C_PINK, fontsize=11, weight="bold")
    _box(ax, (0.0, 1.5), 3.5, 1.6, "Missing-ruleset\ninference", fill=C_YELLOW, fontsize=11, weight="bold")
    _box(ax, (5.0, 3.0), 4.5, 2.7,
         "Autofix +\nIaC Generator",
         fill=C_PURPLE, fontsize=12, weight="bold")
    out_y = [(7.0, "AWS\nTerraform + CFN", C_BLUE),
             (4.0, "Azure\nBicep + az CLI", C_GREEN),
             (1.0, "GCP\nTerraform + gcloud", C_ORANGE)]
    for y, t, c in out_y:
        _box(ax, (11.0, y - 0.7), 4.0, 1.4, t, fill=c, fontsize=11, weight="bold")
        _arrow(ax, 9.5, 4.3, 11.0, y)
    _arrow(ax, 3.5, 5.8, 5.0, 4.7)
    _arrow(ax, 3.5, 2.3, 5.0, 4.0)
    fig.savefig(OUT / "fig16_autofix.png")
    plt.close(fig)


# ── Fig 17: Reporting architecture ─────────────────────────────────────────
def fig17_reporting():
    fig, ax = plt.subplots(figsize=(7.5, 5.5))
    _setup(ax, (-0.3, 16), (-0.3, 11))
    _box(ax, (5.5, 4.0), 5.0, 2.2,
         "Master HTML Report",
         fill=C_PURPLE, fontsize=13, weight="bold")
    inputs = [(0.5, 8.5, "Raw scan\ntelemetry", C_BLUE),
              (5.5, 8.5, "ML metrics\n(P/R/F1, calib.)", C_GREEN),
              (11.0, 8.5, "Ruleset\ninference", C_YELLOW)]
    for x, y, t, c in inputs:
        _box(ax, (x, y - 0.7), 4.0, 1.5, t, fill=c, fontsize=11, weight="bold")
        _arrow(ax, x + 2.0, y - 0.7, 8.0, 6.2)
    outputs = [(0.5, 0.5, "27 charts +\n3D scene", C_BLUE),
               (5.5, 0.5, "MITRE\nATT&CK", C_PINK),
               (11.0, 0.5, "XLSX / CSV /\nJSON", C_ORANGE)]
    for x, y, t, c in outputs:
        _box(ax, (x, y), 4.0, 1.5, t, fill=c, fontsize=11, weight="bold")
        _arrow(ax, 8.0, 4.0, x + 2.0, y + 1.5)
    fig.savefig(OUT / "fig17_reporting.png")
    plt.close(fig)


# ── Fig 18: 9-phase big-picture overview (vertical) ────────────────────────
def fig18_overview():
    fig, ax = plt.subplots(figsize=(5.0, 11.0))
    _setup(ax, (-0.3, 9), (-0.3, 21))
    phases = [
        ("1. INPUT",                  "Target URL",                          C_GREEN),
        ("2. PRE-FLIGHT",             "WAF id + baseline",                   C_BLUE),
        ("3. SCAN",                   "1110 attack payloads",                C_BLUE),
        ("4. CLASSIFY",               "4-layer pipeline",                    C_YELLOW),
        ("5. LEARN",                  "Hybrid ML ensemble",                  C_PURPLE),
        ("6. ATTACK SMARTLY",         "700 AI mutations",                    C_ORANGE),
        ("7. GENERATE FIXES",         "Multi-cloud IaC",                     C_PINK),
        ("8. REPORT",                 "HTML + 3D + XLSX/CSV",                C_BLUE),
        ("9. REMEMBER",               "Cross-scan persistence",              C_GREEN),
    ]
    y = 19.5
    for i, (head, body, c) in enumerate(phases):
        _box(ax, (1.0, y), 7.0, 1.7,
             f"{head}\n{body}",
             fill=c, fontsize=11, weight="bold")
        if i < len(phases) - 1:
            _arrow(ax, 4.5, y, 4.5, y - 0.3)
        y -= 2.15
    fig.savefig(OUT / "fig18_overview.png")
    plt.close(fig)


# ── Fig 19: Full component / module map ────────────────────────────────────
def fig19_full_arch():
    fig, ax = plt.subplots(figsize=(8.0, 6.0))
    _setup(ax, (-0.3, 16), (-0.3, 12))
    _box(ax, (5.5, 9.5), 5.0, 1.5,
         "cli/main.py · Typer entrypoint",
         fill=C_GREEN, fontsize=12, weight="bold")
    pkgs = [(0.0, 6.0, "scanner/",     C_BLUE),
            (3.2, 6.0, "ml/",          C_PURPLE),
            (6.4, 6.0, "report/",      C_PINK),
            (9.6, 6.0, "helpers/",     C_YELLOW),
            (12.8, 6.0, "testcases/",  C_GRAY)]
    for x, y, n, c in pkgs:
        _box(ax, (x, y), 2.7, 1.5, n, fill=c, fontsize=12, weight="bold")
        _arrow(ax, 8.0, 9.5, x + 1.35, y + 1.5)
    fs = [(0.0, 1.5, "./reports/\n(HTML, IaC, JSON)", C_GRAY),
          (5.5, 1.5, "~/.gotestwaf/\nmodels/<waf>/",  C_GRAY),
          (11.0, 1.5, "stdout logs",                  C_GRAY)]
    for x, y, n, c in fs:
        _box(ax, (x, y), 4.5, 1.5, n, fill=c, fontsize=10)
    _arrow(ax, 1.35, 6.0, 2.25, 3.0)
    _arrow(ax, 7.75, 6.0, 7.75, 3.0)
    _arrow(ax, 4.55, 6.0, 5.5, 3.0)
    fig.savefig(OUT / "fig19_full_arch.png")
    plt.close(fig)


def all_figures():
    fig01_algorithm()
    fig02_components()
    fig03_classification()
    fig04_deployment()
    fig05_training()
    fig06_prediction()
    fig14_mutation()
    fig15_persistence()
    fig16_autofix()
    fig17_reporting()
    fig18_overview()
    fig19_full_arch()
    print(f"Wrote 12 colored architecture figures (template-style) to {OUT}")


if __name__ == "__main__":
    all_figures()
