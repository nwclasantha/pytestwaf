"""Insert all 13 figures into pytestwaf-research-article.docx at their
corresponding 'Fig. N.' caption positions.

Figs 1-6  → architecture diagrams from docs/diagrams/
Figs 7-13 → result charts from docs/figures/

Each image is inserted as a centred new paragraph immediately BEFORE the
existing 'Fig. N. ...' caption paragraph, so reading order is image → caption.
"""
from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Inches

DOCX = Path(__file__).parent / "pytestwaf-research-article.docx"
DIAGRAMS = Path(__file__).parent / "diagrams"
FIGURES = Path(__file__).parent / "figures"
PPTX_IMG = Path(__file__).parent / "pptx_extracted"

# Map "Fig. N." → image path. Architecture figures (1-6, 14-19) use the
# polished diagrams from Pytestwaf_System_Architecture.pptx and the Mermaid
# diagrams in docs/diagrams/; result figures (7-13) use the WAF ML analytics
# charts in docs/diagrams/waf-ml-*.png.
FIG_MAP = {
    1:  PPTX_IMG / "slide01.png",        # Complete Scan Lifecycle (algorithm)
    2:  PPTX_IMG / "slide02.png",        # Hybrid WAF validation methodology
    3:  DIAGRAMS / "04-classification.png",  # Four-Layer Classification Pipeline
    4:  DIAGRAMS / "10-deployment.png",  # Experimental architecture / deployment
    5:  DIAGRAMS / "02-training.png",    # Hybrid ML Training Architecture
    6:  DIAGRAMS / "03-prediction.png",  # Hybrid ML Prediction Architecture
    7:  DIAGRAMS / "waf-ml-bypass-distribution.png",         # Predictions on target
    8:  DIAGRAMS / "waf-ml-confusion-matrix.png",            # Model comparison
    9:  DIAGRAMS / "waf-ml-calibration-plot.png",            # Calibration / reliability
    10: DIAGRAMS / "waf-ml-per-class-prf.png",               # Per-class P/R/F1
    11: DIAGRAMS / "waf-ml-feature-importance.png",          # Feature importance
    12: DIAGRAMS / "waf-ml-bypass-by-attack-type.png",       # Bypass by attack type
    13: DIAGRAMS / "waf-ml-class-balance.png",               # Class balance
    14: DIAGRAMS / "05-mutation.png",    # Adaptive Mutation Engine
    15: DIAGRAMS / "07-persistence.png", # Cross-Scan Knowledge Persistence
    16: DIAGRAMS / "06-autofix-iac.png", # Multi-Cloud Autofix & IaC Pipeline
    17: DIAGRAMS / "08-reporting.png",   # Reporting Architecture & Analytics
    18: DIAGRAMS / "01-end-to-end.png",  # Pytestwaf nine-phase pipeline
    19: DIAGRAMS / "09-full-architecture.png",  # Full component architecture
}

# Display widths (inches)
WIDTH = {
    1: 6.0, 2: 5.5, 3: 5.0, 4: 5.5, 5: 6.0, 6: 6.0,
    7: 6.0, 8: 6.0, 9: 5.5, 10: 5.5, 11: 5.5, 12: 5.5, 13: 5.5,
    14: 5.5, 15: 5.5, 16: 5.5, 17: 5.5,
    18: 6.0, 19: 6.0,
}


CAPTION_RE = re.compile(r"^Fig\.\s+(\d+)\.\s")


def _insert_picture_before(doc, target_para, image_path, width_in):
    """Insert a centered image as a new paragraph immediately before
    target_para (which is the figure caption)."""
    # Create a new paragraph element above the target
    target_el = target_para._element
    new_p = target_para._element.makeelement(qn("w:p"), {})
    target_el.addprevious(new_p)

    # Wrap as a python-docx Paragraph and inject the picture
    from docx.text.paragraph import Paragraph
    new_para = Paragraph(new_p, target_para._parent)
    new_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = new_para.add_run()
    run.add_picture(str(image_path), width=Inches(width_in))


def insert_all():
    doc = Document(str(DOCX))
    inserted = []

    for para in list(doc.paragraphs):
        if para.style.name != "figure caption":
            continue
        m = CAPTION_RE.match(para.text.strip())
        if not m:
            continue
        n = int(m.group(1))
        img = FIG_MAP.get(n)
        if img is None or not img.exists():
            print(f"  Fig. {n}: image not found ({img}) — skipping")
            continue
        _insert_picture_before(doc, para, img, WIDTH.get(n, 5.0))
        inserted.append(n)
        print(f"  Fig. {n}: inserted {img.name}")

    doc.save(str(DOCX))
    print(f"\nInserted {len(inserted)} figures: {inserted}")
    print(f"Tables still present: {len(doc.tables)}")


if __name__ == "__main__":
    insert_all()
