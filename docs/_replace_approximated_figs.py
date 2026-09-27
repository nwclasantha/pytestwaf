"""
Replace the three figures and one body claim that involved my approximations.

Figures replaced (each new figure is built from real data only - no made-up
mappings):

  Fig. 27 - was: MITRE ATT&CK technique mapping (made-up technique IDs)
            new: Bypass rate by attack family (keywords objectively extracted
                 from case names: sql, xss, rce, lfi, ldap, xxe, crlf, etc.)

  Fig. 28 - was: Cyber kill-chain phase mapping (made-up phase assignments)
            new: Top-15 feature importances of the deployed ensemble
                 (directly from metrics.json::feature_importance)

  Fig. 29 - was: MITRE tactic coverage radar (made-up tactic mapping)
            new: Per-class precision / recall / F1 grouped bar chart
                 (directly from metrics.json::per_class)

Body claims fixed:

  p213 -- "6 were dropped by the transport layer (non-ASCII / network
          failure)" was my reconciliation invention.  Replaced with a
          neutral statement that 6 base test cases were not classified
          (no claim of root cause).

  p282 -- the descriptive paragraph for Figs. 27/28/29 is rewritten to
          describe the new real-data figures.

Idempotent.  Backup created.
"""
from __future__ import annotations

import csv
import json
import re
import shutil
from collections import Counter, defaultdict
from io import BytesIO
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from PIL import Image
from docx import Document
from docx.oxml.ns import qn

csv.field_size_limit(10_000_000)

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "pytestwaf-research-article.docx"
BAK = ROOT / "pytestwaf-research-article.before-real-data-figs.docx"
METRICS = ROOT / "figures_data" / "metrics.json"
CSV_PATH = ROOT.parent / "reports" / "waf-scan-portal-wazuh-hrclabs-io.csv"
DIAG = ROOT / "diagrams"

# Style (same as the HD pass)
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
    "lines.linewidth": 2.5,
    "lines.markersize": 9,
})

C_BLOCK    = "#0072B2"
C_BYPASS   = "#D55E00"
C_GREEN    = "#009E73"
C_GREY     = "#888888"

FW, FH = 10.0, 6.67
EMU_PER_INCH = 914400
TARGET_W_IN = 3.30


# ---------------------------------------------------------------------------
# Real-data Fig. 27 - bypass rate by attack family (keyword from case name)
# ---------------------------------------------------------------------------
def fig27_attack_family_real(rows):
    """Group cases by an objectively-extracted attack-family keyword."""
    KEYWORDS = [
        ("XSS",                "xss"),
        ("SQL injection",      "sql"),
        ("Command injection",  "shell"),
        ("Command injection",  "rce"),
        ("Command injection",  "command"),
        ("Path traversal / LFI", "lfi"),
        ("Path traversal / LFI", "traversal"),
        ("LDAP injection",     "ldap"),
        ("XML / XXE",          "xxe"),
        ("XML / XXE",          "xml"),
        ("NoSQL injection",    "nosql"),
        ("CRLF injection",     "crlf"),
        ("Mail injection",     "mail"),
        ("Template injection", "template"),
        ("Template injection", "ssti"),
        ("Template injection", "ssi"),
    ]
    counts = defaultdict(lambda: Counter())
    for r in rows:
        case = r["Case"].lower()
        family = None
        for fam, kw in KEYWORDS:
            if kw in case:
                family = fam
                break
        if family is None:
            family = "Other / mixed"
        counts[family][r["Check Status"]] += 1

    families = sorted(counts.keys(),
                      key=lambda f: -(counts[f].get("blocked", 0) + counts[f].get("passed", 0)))
    blocks = [counts[f].get("blocked", 0) for f in families]
    bypass = [counts[f].get("passed", 0)  for f in families]

    y = np.arange(len(families)); h = 0.4
    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.barh(y - h / 2, blocks, h, color=C_BLOCK,  label="Blocked",  edgecolor="white", linewidth=0.8)
    ax.barh(y + h / 2, bypass, h, color=C_BYPASS, label="Bypassed", edgecolor="white", linewidth=0.8)
    ax.set_yticks(y); ax.set_yticklabels(families)
    ax.invert_yaxis()
    ax.legend(loc="lower right", frameon=True)
    ax.set_title("Block vs. bypass count by attack family (keyword from case name)", pad=14)
    ax.set_xlabel("Number of payloads")
    ax.set_ylabel("Attack family")
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    ax.grid(True, axis="x", alpha=0.3, linestyle=":")
    fig.tight_layout()
    p = DIAG / "waf-mitre-attack.png"  # reuse same filename
    fig.savefig(p, dpi=600, bbox_inches="tight", pad_inches=0.18)
    plt.close(fig)
    return p


# ---------------------------------------------------------------------------
# Real-data Fig. 28 - top-15 feature importances
# ---------------------------------------------------------------------------
def fig28_feature_importance(metrics):
    fi = metrics["metrics"]["feature_importance"]  # dict
    items = sorted(fi.items(), key=lambda x: x[1], reverse=True)[:15]
    items = items[::-1]  # ascending for horizontal bar
    names  = [k for k, _ in items]
    values = [v for _, v in items]

    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.barh(names, values, color=C_BLOCK, edgecolor="white", linewidth=0.8)
    for i, v in enumerate(values):
        ax.text(v + max(values) * 0.005, i, f"{v:.4f}", va="center", fontsize=12)
    ax.set_title("Top-15 feature importances of the deployed ensemble", pad=14)
    ax.set_xlabel("Importance (Random Forest gini decrease)")
    ax.set_ylabel("")
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    ax.grid(True, axis="x", alpha=0.3, linestyle=":")
    fig.tight_layout()
    p = DIAG / "waf-kill-chain.png"  # reuse same filename
    fig.savefig(p, dpi=600, bbox_inches="tight", pad_inches=0.18)
    plt.close(fig)
    return p


# ---------------------------------------------------------------------------
# Real-data Fig. 29 - per-class precision / recall / F1
# ---------------------------------------------------------------------------
def fig29_per_class(metrics):
    pc = metrics["metrics"]["per_class"]
    classes = ["blocked", "bypassed"]
    metrics_list = ["precision", "recall", "f1"]
    vals = np.array([[pc[c][m] for m in metrics_list] for c in classes])

    x = np.arange(len(metrics_list)); w = 0.35
    fig, ax = plt.subplots(figsize=(FW, FH))
    bars1 = ax.bar(x - w / 2, vals[0], w, color=C_BLOCK,  label=f"Blocked (n={pc['blocked']['support']})",
                   edgecolor="white", linewidth=0.8)
    bars2 = ax.bar(x + w / 2, vals[1], w, color=C_BYPASS, label=f"Bypassed (n={pc['bypassed']['support']})",
                   edgecolor="white", linewidth=0.8)
    for bars in (bars1, bars2):
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.005,
                    f"{b.get_height():.3f}", ha="center", va="bottom", fontsize=12)
    ax.set_xticks(x)
    ax.set_xticklabels([m.capitalize() for m in metrics_list])
    ax.set_ylim(0.8, 1.02)
    ax.legend(loc="lower right", frameon=True)
    ax.set_title("Per-class precision / recall / F1 of the deployed ensemble", pad=14)
    ax.set_xlabel("Metric")
    ax.set_ylabel("Score")
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    ax.grid(True, axis="y", alpha=0.3, linestyle=":")
    fig.tight_layout()
    p = DIAG / "waf-tactic-radar.png"  # reuse same filename
    fig.savefig(p, dpi=600, bbox_inches="tight", pad_inches=0.18)
    plt.close(fig)
    return p


# ---------------------------------------------------------------------------
# Flatten alpha & set DPI metadata for all three regenerated images
# ---------------------------------------------------------------------------
def flatten(path: Path):
    img = Image.open(path)
    if img.mode == "RGBA":
        bg = Image.new("RGB", img.size, (255, 255, 255))
        bg.paste(img, mask=img.split()[3])
        bg.save(path, format="PNG", optimize=False, compress_level=1, dpi=(600, 600))
    else:
        img.convert("RGB").save(path, format="PNG", optimize=False, compress_level=1, dpi=(600, 600))


# ---------------------------------------------------------------------------
# Body fixes
# ---------------------------------------------------------------------------
def fix_body(doc):
    def replace(p, new):
        p.runs[0].text = new
        for r in p.runs[1:]:
            r.text = ""

    # 1. Replace the invented "6 were dropped by the transport layer" sentence
    for p in doc.paragraphs:
        if "6 were dropped by the transport layer prior to classification" in p.text:
            new = p.text.replace(
                "Of the 1,110 base test cases generated by the corpus, 6 were dropped by the "
                "transport layer prior to classification (non-ASCII payloads not supported by "
                "the underlying httpx client and a small number of transient connection-reset "
                "failures); the remaining 1,104 cases were classified through the four-layer "
                "pipeline and produced 403 blocks (36.5 percent block rate) and 701 bypasses "
                "(63.5 percent bypass rate), with no unresolved cases at termination.",
                "Of the 1,110 base test cases generated by the corpus, 1,104 reached the "
                "supervised training stage through the four-layer pipeline and produced 403 "
                "blocks (36.5 percent block rate) and 701 bypasses (63.5 percent bypass rate), "
                "with no unresolved cases at termination; the remaining 6 cases did not "
                "contribute a labelled triple to training (the underlying cause is not "
                "individually recorded in the metrics artefact).",
                1,
            )
            replace(p, new)
            print("Fixed: invented 'six dropped by transport layer' claim")
            break

    # 2. Replace the descriptive paragraph for Figs. 27/28/29
    for p in doc.paragraphs:
        if (
            "Beyond the primary classification metrics, the framework produces three "
            "complementary security-coverage views" in p.text
            and "MITRE ATT&CK technique" in p.text
        ):
            new = (
                "Beyond the primary classification metrics, three additional figures derived "
                "directly from the scan artefacts complement the per-class diagnostics. Fig. 27 "
                "groups the scan corpus by attack-family keyword extracted objectively from "
                "each case name (XSS, SQL injection, command injection, path traversal, LDAP, "
                "XML/XXE, CRLF, mail injection, template injection, and a residual mixed "
                "category) and reports the per-family block and bypass counts, indicating which "
                "families most urgently require new WAF rules. Fig. 28 reports the top-15 "
                "feature importances of the deployed ensemble taken directly from the trained "
                "Random Forest base estimator, providing an interpretability channel that the "
                "operator can use to audit which payload and response features drive the "
                "ensemble's bypass decisions. Fig. 29 reports the deployed ensemble's per-class "
                "precision, recall, and F1 as a grouped bar chart, exposing the asymmetry "
                "between the blocked and bypassed classes documented quantitatively in "
                "subsection A."
            )
            replace(p, new)
            print("Fixed: rewrote p282 description for Figs. 27/28/29 (real-data only)")
            break

    # 3. Update Fig. 27 caption
    for p in doc.paragraphs:
        if p.style.name == "figure caption" and re.match(r"\s*Fig\.\s*27\.", p.text):
            replace(p, "Fig. 27. Block vs. bypass count by attack family (keyword extracted from case names).")
            print("Fixed: Fig. 27 caption")
            break

    # 4. Update Fig. 28 caption
    for p in doc.paragraphs:
        if p.style.name == "figure caption" and re.match(r"\s*Fig\.\s*28\.", p.text):
            replace(p, "Fig. 28. Top-15 feature importances of the deployed ensemble (Random Forest gini decrease).")
            print("Fixed: Fig. 28 caption")
            break

    # 5. Update Fig. 29 caption
    for p in doc.paragraphs:
        if p.style.name == "figure caption" and re.match(r"\s*Fig\.\s*29\.", p.text):
            replace(p, "Fig. 29. Per-class precision, recall, and F1 of the deployed ensemble.")
            print("Fixed: Fig. 29 caption")
            break


# ---------------------------------------------------------------------------
# Re-embed images at JCM column width
# ---------------------------------------------------------------------------
def re_embed(doc):
    drawing_qn = qn("w:drawing"); blip_qn = qn("a:blip"); embed_qn = qn("r:embed")
    extent_qn = qn("wp:extent"); ext_a_qn = qn("a:ext")

    target_cx = int(TARGET_W_IN * EMU_PER_INCH)
    rels = doc.part.related_parts

    pending = None; pending_part = None
    for p in doc.paragraphs:
        for d in p._p.iter(drawing_qn):
            pending = d
            for blip in d.iter(blip_qn):
                rid = blip.get(embed_qn)
                if rid: pending_part = rels[rid]
        if p.style.name == "figure caption":
            m = re.match(r"\s*Fig\.\s*(\d+)", p.text)
            if m:
                fig_n = int(m.group(1))
                file_map = {
                    27: "waf-mitre-attack.png",
                    28: "waf-kill-chain.png",
                    29: "waf-tactic-radar.png",
                }
                if fig_n in file_map and pending is not None and pending_part is not None:
                    src = DIAG / file_map[fig_n]
                    if src.exists():
                        pending_part._blob = src.read_bytes()
                        img = Image.open(src)
                        ratio = img.size[0] / img.size[1]
                        new_cy = int(round(target_cx / ratio))
                        ex = next(pending.iter(extent_qn), None)
                        if ex is not None:
                            ex.set("cx", str(target_cx))
                            ex.set("cy", str(new_cy))
                        for ae in pending.iter(ext_a_qn):
                            ae.set("cx", str(target_cx))
                            ae.set("cy", str(new_cy))
                        print(f"Re-embedded Fig. {fig_n}: {img.size[0]}x{img.size[1]} "
                              f"-> {TARGET_W_IN:.2f}x{new_cy/EMU_PER_INCH:.2f}\"")
                pending = None; pending_part = None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if not BAK.exists():
        shutil.copyfile(DOC, BAK)
        print(f"Backup written: {BAK}")

    metrics = json.loads(METRICS.read_text(encoding="utf-8"))
    rows = list(csv.DictReader(open(CSV_PATH, encoding="utf-8")))

    # Generate the three new real-data figures
    p27 = fig27_attack_family_real(rows)
    p28 = fig28_feature_importance(metrics)
    p29 = fig29_per_class(metrics)
    flatten(p27); flatten(p28); flatten(p29)
    print(f"Wrote new PNGs: {p27.name}, {p28.name}, {p29.name}")

    # Apply body and caption fixes, then re-embed
    doc = Document(str(DOC))
    fix_body(doc)
    re_embed(doc)
    doc.save(str(DOC))
    print(f"\nSaved: {DOC}")


if __name__ == "__main__":
    main()
