"""
Align pytestwaf-research-article.docx structure to the approved template
JCM-20514-v5-fixed.docx. Three deltas were identified:

  1. Section 5 H1 title:   'Methodology' -> 'Proposed Hybrid ML-Based Solution'
  2. Abstract separator:   'Abstract, '  -> 'Abstract—' (em-dash, no space)
  3. Keywords separator:   'Keywords, '  -> 'Keywords—' (em-dash, no space)

All other H1/H2 sections, ordering, and end-matter (Conflict of Interest,
Author Contributions, References) already match the template.

Idempotent: re-running is a no-op once changes have been applied.
"""

import shutil
from pathlib import Path

from docx import Document

DOC = Path("pytestwaf-research-article.docx")
BAK = Path("pytestwaf-research-article.before-template-align.docx")

EM_DASH = "—"


def main():
    if not DOC.exists():
        raise SystemExit(f"Cannot find {DOC.resolve()}")
    if not BAK.exists():
        shutil.copyfile(DOC, BAK)
        print(f"Backup written: {BAK}")

    doc = Document(str(DOC))
    changes = 0

    # ---- 1. Rename Section 5 H1 -------------------------------------------
    for p in doc.paragraphs:
        if p.style.name == "Heading 1" and p.text.strip() == "Methodology":
            for r in p.runs:
                r.text = ""
            p.runs[0].text = "Proposed Hybrid ML-Based Solution"
            print("Renamed H1: 'Methodology' -> 'Proposed Hybrid ML-Based Solution'")
            changes += 1
            break
    else:
        print("Section 5 H1 already renamed (or not found).")

    # ---- 2 & 3. Abstract / Keywords separator -----------------------------
    for p in doc.paragraphs:
        if p.style.name != "Abstract":
            continue
        if not p.runs:
            continue
        first = p.runs[0]
        # 'Abstract, X' -> 'Abstract—X'   (no space after em-dash, IEEE style)
        if first.text.startswith("Abstract, "):
            first.text = "Abstract" + EM_DASH + first.text[len("Abstract, "):]
            print("Abstract separator: ', ' -> em-dash")
            changes += 1
        elif first.text.startswith("Keywords, "):
            first.text = "Keywords" + EM_DASH + first.text[len("Keywords, "):]
            print("Keywords separator: ', ' -> em-dash")
            changes += 1

    if changes == 0:
        print("No changes needed - document already matches template.")
    doc.save(str(DOC))
    print(f"Saved: {DOC} ({changes} change(s))")


if __name__ == "__main__":
    main()
