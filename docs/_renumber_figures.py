"""
Renumber the newly inserted confusion-matrix / reliability figures so the
document's figure numbers are monotonic in document order.

Current state (document order):
    Fig. 24 (top-risk bypass)              -> stays Fig. 24
    Fig. 28 (NEW confusion matrix)         -> becomes Fig. 25
    Fig. 29 (NEW reliability)              -> becomes Fig. 26
    Fig. 25 (MITRE ATT&CK)                 -> becomes Fig. 27
    Fig. 26 (kill-chain)                   -> becomes Fig. 28
    Fig. 27 (MITRE tactic radar)           -> becomes Fig. 29

We update both captions AND every in-text reference, applying the changes
in a temporary-token order so we never collide with an already-shifted
number.

Idempotent: re-running detects "Fig. 25" carrying confusion-matrix wording
and exits.
"""
from pathlib import Path
import re
from docx import Document

DOC = Path("pytestwaf-research-article.docx")


def main():
    doc = Document(str(DOC))

    # Idempotency guard
    for p in doc.paragraphs:
        if p.style.name == "figure caption" and p.text.startswith(
            "Fig. 25. Confusion matrix"
        ):
            print("Already renumbered - exiting.")
            return

    # Phase A: rewrite via temporary tokens to avoid collisions
    # Old -> Tmp
    a_map = {
        "Fig. 25": "Fig. T27",
        "Fig. 26": "Fig. T28",
        "Fig. 27": "Fig. T29",
        "Fig. 28": "Fig. T25",
        "Fig. 29": "Fig. T26",
    }
    # Tmp -> New
    b_map = {
        "Fig. T25": "Fig. 25",
        "Fig. T26": "Fig. 26",
        "Fig. T27": "Fig. 27",
        "Fig. T28": "Fig. 28",
        "Fig. T29": "Fig. 29",
    }

    def rewrite_para(p, mapping):
        if not p.runs:
            return False
        new_text = p.text
        changed = False
        for old, new in mapping.items():
            if old in new_text:
                new_text = new_text.replace(old, new)
                changed = True
        if changed:
            p.runs[0].text = new_text
            for r in p.runs[1:]:
                r.text = ""
        return changed

    a_count = 0
    b_count = 0
    for p in doc.paragraphs:
        if rewrite_para(p, a_map):
            a_count += 1
    for p in doc.paragraphs:
        if rewrite_para(p, b_map):
            b_count += 1
    # also process figure-caption paragraphs (already in doc.paragraphs above)

    print(f"Phase A (Old -> Tmp) edits: {a_count}")
    print(f"Phase B (Tmp -> New) edits: {b_count}")

    doc.save(str(DOC))
    print(f"Saved: {DOC}")


if __name__ == "__main__":
    main()
