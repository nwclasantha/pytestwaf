"""Generate two JCM-style block diagrams for pytestwaf.

  Fig. 1  fig01_algorithm.png    -  algorithm flowchart
  Fig. 2  fig02_methodology.png  -  methodology hierarchy

Design constraints:
  * Large, readable fonts (12-14pt body, 16-18pt headers)
  * Generous box sizes and whitespace
  * Renders cleanly when scaled to a 6-inch column width in Word
"""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Polygon

OUT = Path(__file__).parent / "diagrams"
OUT.mkdir(exist_ok=True)

# -- palette -----------------------------------------------------------------
INPUT_FILL  = "#dcecfb"
INPUT_EDGE  = "#1f6fb4"
PREP_FILL   = "#fde6c4"
PREP_EDGE   = "#cf7a1d"
TRAIN_FILL  = "#e6d6ee"
TRAIN_EDGE  = "#6a3990"
DEC_FILL    = "#fad6d6"
DEC_EDGE    = "#a02828"
BAD_FILL    = "#fad6d6"
BAD_EDGE    = "#a02828"
GOOD_FILL   = "#d2eccf"
GOOD_EDGE   = "#2c7a2c"
OUT_FILL    = "#d2eccf"
OUT_EDGE    = "#2c7a2c"
HEADER_FILL = "#b3dab1"
HEADER_EDGE = "#2c7a2c"
SUB_FILL    = "#dcecfb"
SUB_EDGE    = "#3f86c2"
GROUP_EDGE  = "#444444"
ARROW_COLOR = "#222222"


# -- primitives --------------------------------------------------------------

def box(ax, x, y, w, h, text, fill, edge, fontsize=12, bold=False, italic=False):
    p = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.04,rounding_size=0.10",
        facecolor=fill, edgecolor=edge, linewidth=1.6, zorder=2,
    )
    ax.add_patch(p)
    weight = "bold" if bold else "normal"
    style = "italic" if italic else "normal"
    ax.text(x + w / 2, y + h / 2, text,
            ha="center", va="center",
            fontsize=fontsize, weight=weight, style=style,
            zorder=3)


def diamond(ax, cx, cy, w, h, text, fill, edge, fontsize=13):
    pts = [(cx, cy + h / 2), (cx + w / 2, cy),
           (cx, cy - h / 2), (cx - w / 2, cy)]
    poly = Polygon(pts, closed=True, facecolor=fill, edgecolor=edge,
                   linewidth=1.8, zorder=2)
    ax.add_patch(poly)
    ax.text(cx, cy, text, ha="center", va="center",
            fontsize=fontsize, weight="bold", zorder=3)


def arrow(ax, x1, y1, x2, y2, color=ARROW_COLOR, lw=1.4, ls="-"):
    a = FancyArrowPatch(
        (x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=18,
        color=color, linewidth=lw, linestyle=ls, zorder=1,
    )
    ax.add_patch(a)


def group_label(ax, x, y, w, h, text, color=GROUP_EDGE):
    rect = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.0,rounding_size=0.06",
        facecolor="none", edgecolor=color,
        linewidth=1.6, linestyle="--", zorder=1,
    )
    ax.add_patch(rect)
    ax.text(x + w / 2, y + h - 0.45, text, ha="center", va="center",
            fontsize=15, weight="bold", color=color, zorder=4,
            bbox=dict(facecolor="white", edgecolor="none", pad=4))


# ============================================================================
# Fig. 1  Algorithm flowchart
# ============================================================================

def build_algorithm():
    # Wider canvas, taller boxes, larger margin between groups.
    fig, ax = plt.subplots(figsize=(16, 22), dpi=180)
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 22)
    ax.set_aspect("equal")
    ax.axis("off")

    # ===== INPUTS row =======================================================
    group_label(ax, 0.5, 19.8, 15.0, 1.9, "INPUTS", INPUT_EDGE)
    in_specs = [
        (1.1,  20.0, "Target URLs\n(U)"),
        (4.7,  20.0, "Test Corpus\n47 YAML / 7 sets (C)"),
        (8.3,  20.0, "Mutation Budget\nN_a = 700"),
        (11.9, 20.0, "Threshold\nτ = 0.5"),
    ]
    for x, y, text in in_specs:
        box(ax, x, y, 3.2, 1.2, text, INPUT_FILL, INPUT_EDGE, fontsize=13, bold=True)

    # ===== DATA PREPROCESSING (left column) =================================
    group_label(ax, 0.5, 11.6, 7.0, 7.9, "DATA PREPROCESSING", PREP_EDGE)
    prep_x = 1.0
    prep_w = 6.0
    prep = [
        ("Launch Stealth Browser\nctx ← LAUNCH(U)\n+ stealth init script", 18.10),
        ("Solve Cloudflare Challenge\nwait for cf_clearance",              16.85),
        ("Capture Baseline ×3\nB ← CAPTURE_BASELINE(ctx)",                 15.60),
        ("Detect WAF Vendor\nV ← DETECT_WAF(B)",                           14.35),
        ("Materialise Cartesian Corpus\nP ← payload × encoder × placeholder", 13.10),
        ("Extract 72-D Features\n52 payload + 20 response",                11.85),
    ]
    prev_y = None
    for text, y in prep:
        box(ax, prep_x, y, prep_w, 1.05, text, PREP_FILL, PREP_EDGE, fontsize=12)
        if prev_y is not None:
            arrow(ax, prep_x + prep_w / 2, prev_y, prep_x + prep_w / 2, y + 1.05)
        prev_y = y

    # Inputs -> top of preprocessing
    arrow(ax, 2.6, 20.0, 2.6, 18.10 + 1.05)
    arrow(ax, 6.3, 20.0, 4.6, 18.10 + 1.05)

    # ===== MODEL TRAINING (left column, below preprocessing) ================
    group_label(ax, 0.5, 6.0, 7.0, 5.4, "MODEL TRAINING", TRAIN_EDGE)
    # 3 base models in a row
    box(ax, 0.8, 9.5, 1.95, 1.3, "Train RF\nM_rf\nn=200, d=6",          TRAIN_FILL, TRAIN_EDGE, fontsize=12)
    box(ax, 3.0, 9.5, 1.95, 1.3, "Train GB\nM_gb\nn=120, lr=0.08",      TRAIN_FILL, TRAIN_EDGE, fontsize=12)
    box(ax, 5.2, 9.5, 1.95, 1.3, "Train MLP\nM_mlp\n(48,24)",           TRAIN_FILL, TRAIN_EDGE, fontsize=12)

    # Decision diamond
    diamond(ax, 4.0, 8.4, 4.4, 1.1, "minority ≥ 10 ?", DEC_FILL, DEC_EDGE, fontsize=12)

    # Yes branch: Stacking + Calibrate
    box(ax, 0.8, 6.6, 2.95, 1.2, "Stacking Meta\nLogReg(C=0.5)\nbalanced", TRAIN_FILL, TRAIN_EDGE, fontsize=12)
    box(ax, 4.0, 6.6, 2.95, 1.2, "Calibrate (isotonic)\nStratifiedKFold",   TRAIN_FILL, TRAIN_EDGE, fontsize=12)

    # No branch: RF fallback (italic)
    box(ax, 7.65, 8.05, 2.4, 1.1, "RF fallback\nn=150, d=6\nbalanced",
        TRAIN_FILL, TRAIN_EDGE, fontsize=11, italic=True)

    # Wiring: features -> trainers
    arrow(ax, prep_x + prep_w / 2, 11.85, 1.78, 9.5 + 1.3)
    arrow(ax, prep_x + prep_w / 2, 11.85, 3.98, 9.5 + 1.3)
    arrow(ax, prep_x + prep_w / 2, 11.85, 6.18, 9.5 + 1.3)

    # Trainers -> diamond
    arrow(ax, 1.78, 9.5, 2.7, 8.7)
    arrow(ax, 3.98, 9.5, 4.0, 8.95)
    arrow(ax, 6.18, 9.5, 5.3, 8.7)

    # Diamond Yes -> Stacking; Stacking -> Calibrate
    arrow(ax, 2.5, 8.0, 2.27, 7.80)
    ax.text(2.0, 8.20, "Yes", fontsize=12, color=GOOD_EDGE, weight="bold")
    arrow(ax, 3.75, 7.20, 4.00, 7.20)

    # Diamond No -> RF fallback (dashed)
    arrow(ax, 5.5, 8.0, 7.65, 8.4, ls="--")
    ax.text(6.4, 8.50, "No", fontsize=12, color=BAD_EDGE, weight="bold")

    # ===== FOR EACH PAYLOAD (right column) ==================================
    group_label(ax, 8.0, 4.2, 7.5, 15.3, "FOR EACH (cat, p, e, ph) IN C", PREP_EDGE)
    loop_x = 8.4
    loop_w = 6.7
    loop = [
        ("Encode Payload\np′ ← ENCODE(p, e)",                            18.10),
        ("Submit Request\nr ← SUBMIT(ctx, p′, ph)",                       16.85),
        ("Layer 1 — WAF Signature\nmatchVendorSignature(r, V) ?",         15.60),
        ("Layer 2 — Jaccard Baseline Diff\nsim ← |Tr ∩ Tb| / |Tr ∪ Tb|",  14.35),
        ("Layer 2.5 — MLP Autoencoder\na ← reconstructionError(r)",       13.10),
        ("Layer 3 — Online k-Means\nk ← clusterAssign(r)",                11.85),
        ("Score Mutation Candidate\nP_bypass ← M.predict_proba(f)",       10.20),
    ]
    prev_y = None
    for text, y in loop:
        box(ax, loop_x, y, loop_w, 1.05, text, PREP_FILL, PREP_EDGE, fontsize=12)
        if prev_y is not None:
            arrow(ax, loop_x + loop_w / 2, prev_y, loop_x + loop_w / 2, y + 1.05)
        prev_y = y

    # Decision: P_bypass >= τ
    diamond(ax, 11.75, 9.0, 5.0, 1.1, "P_bypass ≥ τ ?", DEC_FILL, DEC_EDGE, fontsize=13)
    arrow(ax, 11.75, 10.20, 11.75, 9.55)

    # Yes -> bypassed
    box(ax, 8.4,  7.0, 3.0, 1.4, "ℓ ← BYPASSED\n(append to T)\nfeed mutation engine",
        BAD_FILL, BAD_EDGE, fontsize=12, bold=True)
    arrow(ax, 10.5, 8.5, 9.9, 8.4)
    ax.text(9.6, 8.70, "Yes", fontsize=12, color=BAD_EDGE, weight="bold")

    # No -> blocked
    box(ax, 12.1, 7.0, 3.0, 1.4, "ℓ ← BLOCKED\n(skip)",
        GOOD_FILL, GOOD_EDGE, fontsize=12, bold=True)
    arrow(ax, 13.0, 8.5, 13.6, 8.4)
    ax.text(13.30, 8.70, "No", fontsize=12, color=GOOD_EDGE, weight="bold")

    # Bypassed -> UPDATE_KNOWLEDGE
    box(ax, 8.4, 5.0, 6.7, 1.5,
        "UPDATE_KNOWLEDGE(bypass, missing rule)\n+ generate adaptive mutations  Q (700)\n→ refit M with new evidence",
        BAD_FILL, BAD_EDGE, fontsize=12)
    arrow(ax, 9.9, 7.0, 9.9, 6.5)
    arrow(ax, 13.6, 7.0, 13.6, 6.5)

    # Cross-flow dashed: features -> loop & model -> score
    arrow(ax, 7.0, 12.4, 8.4, 13.6, ls="--", color="#7a7a7a")
    arrow(ax, 5.4, 7.20, 8.4, 10.7, ls="--", color="#7a7a7a")

    # ===== OUTPUTS row ======================================================
    group_label(ax, 0.5, 1.4, 15.0, 2.4, "OUTPUTS", OUT_EDGE)
    out_specs = [
        (0.9,  1.6, "Per-Payload Labels\n(L)\nblocked / bypassed / unresolved / failed"),
        (4.5,  1.6, "Trained Stacking Model\n(M)\njoblib persisted"),
        (8.1,  1.6, "Knowledge Artefacts\n(K)\nbypasses, missing rules, history"),
        (11.7, 1.6, "Multi-Cloud IaC\n(F)\nTerraform / Bicep / gcloud / boto3"),
    ]
    for x, y, text in out_specs:
        box(ax, x, y, 3.4, 1.7, text, OUT_FILL, OUT_EDGE, fontsize=12, bold=True)

    arrow(ax, 5.5, 5.0, 5.5, 3.30)
    arrow(ax, 12.5, 5.0, 12.5, 3.30)
    arrow(ax, 4.0, 6.6, 6.0, 3.30, ls="--", color="#7a7a7a")

    # Title
    ax.text(8.0, 0.5,
            "Algorithm 1 — Hybrid ML-Based WAF Validation (pytestwaf)",
            ha="center", va="center", fontsize=16, weight="bold")

    fig.tight_layout()
    out = OUT / "fig01_algorithm.png"
    fig.savefig(out, dpi=180, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  wrote {out.name}  ({out.stat().st_size//1024} KB)")


# ============================================================================
# Fig. 2  Methodology hierarchy
# ============================================================================

def build_methodology():
    # Wider canvas, taller boxes for readability.
    fig, ax = plt.subplots(figsize=(18, 14), dpi=180)
    ax.set_xlim(0, 22)
    ax.set_ylim(0, 17)
    ax.set_aspect("equal")
    ax.axis("off")

    # Root
    box(ax, 8.0, 15.4, 6.0, 1.2, "WAF Validation Management",
        HEADER_FILL, HEADER_EDGE, fontsize=18, bold=True)

    # 5 column headers
    col_x = [0.5, 4.7, 9.0, 13.3, 17.6]
    col_w = 3.9
    col_titles = [
        "Methodology for\nTest Corpus",
        "Methodology for\nScan Execution",
        "Four-Layer Response\nClassification",
        "Hybrid ML Engine\n(4-Layer Stack)",
        "Methodology for\nMulti-Cloud Auto-Remediation",
    ]
    header_y = 13.4
    header_h = 1.4
    for x, t in zip(col_x, col_titles):
        box(ax, x, header_y, col_w, header_h, t,
            HEADER_FILL, HEADER_EDGE, fontsize=13, bold=True)
        # connector from root
        arrow(ax, 11.0, 15.4, x + col_w / 2, header_y + header_h)

    # Sub-items per column
    sub_h = 1.05
    sub_gap = 0.30
    branches = [
        # Test Corpus
        ["OWASP Top 10 Set\n(14 YAML files)",
         "OWASP API Security Set",
         "Community-Curated Set",
         "Industry Sets\n(Finance / Gov / Health)",
         "False-Positive Control Set",
         "6 encoders × 14 placeholders\nCartesian materialisation"],
        # Scan Execution
        ["Stealth Browser Launch\n(Playwright + init script)",
         "Cloudflare Challenge Solver\n(wait for cf_clearance)",
         "Baseline Capture × 3\n(detectBlockPage)",
         "WAF Vendor Detection\n(layer-0 fingerprint)",
         "Async Worker Pool\n(httpx + jitter)",
         "Token-Bucket Rate Limiter"],
        # Four-Layer Classification
        ["Layer 1: Vendor Signature\nregex match",
         "Layer 2: Stable-Token Jaccard\n(0.6 / 0.3 thresholds)",
         "Layer 2: WAF-Keyword Score\n(22 vendor-neutral phrases)",
         "Layer 2.5: MLP Autoencoder\nreconstruction error",
         "Layer 3: Online k-Means\nknown block-page clusters",
         "Outcome:\nblocked / bypassed / unresolved"],
        # Hybrid ML Engine
        ["Layer 1: Rule-Based Classifier",
         "Layer 2: IsolationForest\n+ Local Outlier Factor",
         "Layer 3: Stacking Ensemble\nRF₂₀₀ + GB₁₂₀ + MLP",
         "Logistic Regression\nMeta-Learner C=0.5",
         "Isotonic Probability\nCalibration",
         "Layer 4: Drift Detector\n(KS-test + PSI)"],
        # Multi-Cloud Auto-Remediation
        ["AWS Terraform\n+ CloudFormation",
         "Azure Bicep + az CLI",
         "GCP Terraform + gcloud",
         "boto3 Non-Destructive\nDeploy Script",
         "MITRE ATT&CK Mapping",
         "HTML / 3D / XLSX / CSV\nReports"],
    ]

    for col_idx, items in enumerate(branches):
        x = col_x[col_idx]
        # First sub starts below header
        first_top = header_y - sub_gap
        # connector header bottom -> first sub top
        for i, t in enumerate(items):
            y_top = first_top - i * (sub_h + sub_gap)
            y = y_top - sub_h
            box(ax, x, y, col_w, sub_h, t, SUB_FILL, SUB_EDGE, fontsize=11)
            if i == 0:
                arrow(ax, x + col_w / 2, header_y, x + col_w / 2, y_top)
            else:
                prev_bottom = first_top - (i - 1) * (sub_h + sub_gap) - sub_h
                arrow(ax, x + col_w / 2, prev_bottom, x + col_w / 2, y_top)

    # Bottom flow boxes
    box(ax, 1.5, 0.6, 7.0, 1.5,
        "Real-Time WAF Validation\nwith Hybrid ML Generated Models\n(Algorithm 1)",
        "#f1f1f1", "#666666", fontsize=13, bold=True)
    box(ax, 13.5, 0.6, 7.0, 1.5,
        "Multi-Cloud Auto-Remediation Pipeline\nTerraform · Bicep · gcloud · boto3",
        "#f1f1f1", "#666666", fontsize=13, bold=True)
    arrow(ax, 8.5, 1.35, 13.5, 1.35, lw=2.0)

    # Dashed arrows from ML Engine + IaC columns down to bottom flow
    bottom_y = header_y - 6 * (sub_h + sub_gap) - sub_h
    arrow(ax, col_x[3] + col_w / 2, bottom_y, 5.0, 2.10, ls="--", color="#666666")
    arrow(ax, col_x[4] + col_w / 2, bottom_y, 17.0, 2.10, ls="--", color="#666666")

    fig.tight_layout()
    out = OUT / "fig02_methodology.png"
    fig.savefig(out, dpi=180, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  wrote {out.name}  ({out.stat().st_size//1024} KB)")


if __name__ == "__main__":
    print("Building JCM-style figures for pytestwaf (large fonts)...")
    build_algorithm()
    build_methodology()
    print("Done.")
