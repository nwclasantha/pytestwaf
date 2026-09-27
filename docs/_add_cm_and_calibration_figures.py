"""
Add Fig. 28 (confusion matrix) and Fig. 29 (calibration / reliability diagram)
to pytestwaf-research-article.docx.  Both PNGs already exist on disk under
diagrams/.  Also clean up the four figure captions that still contain the
" ,  " em-dash placeholder typo.

Inserts:
  - Fig. 28 image + caption + reference paragraph at the end of Results §E
    (before the Discussion H1)
  - Fig. 29 image + caption + reference paragraph immediately after Fig. 28
  - Body sentence in §E that references both figures

Idempotent: re-running is a no-op.  Backup is created on first run.
"""

import shutil
from copy import deepcopy
from pathlib import Path

from docx import Document
from docx.shared import Inches

DOC = Path("pytestwaf-research-article.docx")
BAK = Path("pytestwaf-research-article.before-cm-figures.docx")
CM_PNG = Path("diagrams/waf-ml-confusion-matrix.png")
CAL_PNG = Path("diagrams/waf-ml-calibration-plot.png")

EM = "—"


def add_paragraph_with_image(doc, image_path, width_inches=5.5):
    """Append an empty 'Normal'-style paragraph with an embedded picture.
    Returns the paragraph."""
    p = doc.add_paragraph(style="Normal")
    run = p.add_run()
    run.add_picture(str(image_path), width=Inches(width_inches))
    return p


def move_paragraph_before(p_to_move, p_anchor):
    """Move paragraph element p_to_move to immediately before p_anchor."""
    body = p_anchor._p.getparent()
    body.remove(p_to_move._p)
    idx = list(body).index(p_anchor._p)
    body.insert(idx, p_to_move._p)


def main():
    if not DOC.exists():
        raise SystemExit(f"Cannot find {DOC.resolve()}")
    if not CM_PNG.exists() or not CAL_PNG.exists():
        raise SystemExit("Image files missing")
    if not BAK.exists():
        shutil.copyfile(DOC, BAK)
        print(f"Backup written: {BAK}")

    doc = Document(str(DOC))

    # Idempotency: if Fig. 28 caption already present, exit
    for p in doc.paragraphs:
        if p.style.name == "figure caption" and "Fig. 28" in p.text:
            print("Fig. 28 already present - nothing to do.")
            return

    # ---------------------------------------------------------------- #
    # Fix four figure-caption em-dash placeholders that survived Batch 1
    # ---------------------------------------------------------------- #
    caption_fixes = {
        "Fig. 1. Pytestwaf nine-phase pipeline ,  big-picture overview.":
            "Fig. 1. Pytestwaf nine-phase pipeline" + EM + "big-picture overview.",
        "Fig. 4. Full component architecture ,  module-level map.":
            "Fig. 4. Full component architecture" + EM + "module-level map.",
        "Fig. 6. Adaptive mutation engine ,  five-stage autonomous cycle.":
            "Fig. 6. Adaptive mutation engine" + EM + "five-stage autonomous cycle.",
        "Fig. 7. Cross-scan knowledge persistence ,  strictly keyed by WAF type.":
            "Fig. 7. Cross-scan knowledge persistence" + EM + "strictly keyed by WAF type.",
    }
    cap_fixes = 0
    for p in doc.paragraphs:
        if p.style.name != "figure caption":
            continue
        for old, new in caption_fixes.items():
            if p.text.strip() == old:
                p.runs[0].text = new
                for r in p.runs[1:]:
                    r.text = ""
                cap_fixes += 1
                break
    print(f"Caption em-dash fixes: {cap_fixes}/4")

    # ---------------------------------------------------------------- #
    # Find the Discussion H1 (insertion point — figures go right before it,
    # i.e. at the end of Results §E)
    # ---------------------------------------------------------------- #
    discussion = None
    for p in doc.paragraphs:
        if p.style.name == "Heading 1" and p.text.strip() == "Discussion":
            discussion = p
            break
    if discussion is None:
        raise SystemExit("Cannot find Discussion H1")

    # ---------------------------------------------------------------- #
    # Body text introducing the new figures (placed before the figures)
    # ---------------------------------------------------------------- #
    intro_p = doc.add_paragraph(
        "Fig. 28 visualises the aggregate confusion matrix of the deployed calibrated stacking "
        "ensemble computed by summing the five fold-level confusion matrices and reporting the "
        "totals on the bypass-detection task. Of the 1,104 classified test cases, 359 of the 403 "
        "true blocks are correctly recovered (44 false bypasses) and 665 of the 701 true bypasses "
        "are correctly recovered (36 false blocks); the diagonal dominance is consistent with the "
        "per-class precision and recall reported in subsection A. Fig. 29 reports the corresponding "
        "10-bin reliability diagram. The diagonal reference line indicates perfect calibration, the "
        "step plot shows the empirical bypass frequency in each predicted-probability bin, and the "
        "shaded population bars at the foot of the plot give the per-bin sample count. The deployed "
        "ensemble is well calibrated above predicted probability 0.7 and slightly under-confident in "
        "the 0.3-0.6 range, which is the regime accounting for most of the ECE = 0.094 reported in "
        "subsection E.",
        style="Body Text",
    )

    # ---------------------------------------------------------------- #
    # Fig. 28 — confusion matrix
    # ---------------------------------------------------------------- #
    cm_pic = add_paragraph_with_image(doc, CM_PNG, width_inches=4.5)
    cm_cap = doc.add_paragraph(
        "Fig. 28. Confusion matrix of the deployed calibrated stacking ensemble (aggregated across the 5 cross-validation folds; columns: predicted; rows: actual).",
        style="figure caption",
    )

    # ---------------------------------------------------------------- #
    # Fig. 29 — calibration / reliability diagram
    # ---------------------------------------------------------------- #
    cal_pic = add_paragraph_with_image(doc, CAL_PNG, width_inches=5.0)
    cal_cap = doc.add_paragraph(
        "Fig. 29. Reliability diagram of the deployed calibrated stacking ensemble; predicted bypass probability versus empirical bypass frequency in 10 equal-width bins, with per-bin population shown beneath the curve.",
        style="figure caption",
    )

    # The new paragraphs are appended at the end of the document. Move them
    # all to immediately before the Discussion heading, in order.
    move_paragraph_before(intro_p, discussion)
    move_paragraph_before(cm_pic, discussion)
    move_paragraph_before(cm_cap, discussion)
    move_paragraph_before(cal_pic, discussion)
    move_paragraph_before(cal_cap, discussion)

    print("Inserted Fig. 28 (confusion matrix) and Fig. 29 (reliability diagram)")

    doc.save(str(DOC))
    print(f"Saved: {DOC}")


if __name__ == "__main__":
    main()
