"""Apply blue color (0000FF) to figure captions + inline 'Fig. N'
references in pytestwaf-research-article.docx.

This mirrors the IEEE/journal convention where cross-references and
figure callouts appear in blue (Hyperlink-style colour).
"""
from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path

from docx import Document
from docx.oxml.ns import qn
from docx.shared import RGBColor

DOCX = Path(__file__).parent / "pytestwaf-research-article.docx"
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
BLUE = "0000FF"

# Match inline figure references in body text (with or without period after digit)
FIG_INLINE_RE = re.compile(r"Fig\.\s+\d+(?:\.|\b)")


def _set_run_color(r_elem, color_hex: str) -> None:
    """Apply <w:color w:val=…/> to a run element."""
    rpr = r_elem.find(W + "rPr")
    if rpr is None:
        rpr = r_elem.makeelement(W + "rPr", {})
        r_elem.insert(0, rpr)
    # Remove existing color
    for c in rpr.findall(W + "color"):
        rpr.remove(c)
    color = rpr.makeelement(W + "color", {})
    color.set(W + "val", color_hex)
    rpr.append(color)


def _split_run_around_match(p_elem, match_start: int, match_end: int,
                            full_text: str) -> None:
    """Re-build the paragraph so that the substring [match_start:match_end]
    of full_text becomes its own coloured run, while the surrounding text
    stays in its original (uncoloured) runs.

    This is implemented by: collect all original runs (with their
    formatting), reconstruct the text with a 3-way split, and rebuild
    the paragraph's runs in document order.
    """
    # Collect all runs and their text + formatting clones
    original_runs = list(p_elem.iter(W + "r"))
    if not original_runs:
        return

    # Use the FIRST run as the formatting carrier (clone it for each chunk)
    template_r = original_runs[0]

    # Strip all <w:r> from the paragraph (keep <w:pPr> if present)
    pPr = p_elem.find(W + "pPr")
    for r in p_elem.findall(W + "r"):
        p_elem.remove(r)

    # Determine 3 chunks
    pre = full_text[:match_start]
    mid = full_text[match_start:match_end]
    post = full_text[match_end:]

    # Helper to make a coloured/uncoloured run with specific text
    def _make_run(text: str, blue: bool):
        new_r = deepcopy(template_r)
        # Strip existing text elements
        for t in new_r.findall(W + "t"):
            new_r.remove(t)
        new_t = new_r.makeelement(W + "t", {})
        new_t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        new_t.text = text
        new_r.append(new_t)
        if blue:
            _set_run_color(new_r, BLUE)
        else:
            # Strip any color from the carrier run
            rpr = new_r.find(W + "rPr")
            if rpr is not None:
                for c in rpr.findall(W + "color"):
                    rpr.remove(c)
        return new_r

    if pre:
        p_elem.append(_make_run(pre, blue=False))
    p_elem.append(_make_run(mid, blue=True))
    if post:
        p_elem.append(_make_run(post, blue=False))


def _paragraph_text(p_elem) -> str:
    return "".join((t.text or "") for t in p_elem.iter(W + "t"))


def main():
    doc = Document(str(DOCX))

    n_caps = n_inlines = 0

    for p in doc.paragraphs:
        style_name = p.style.name
        text = p.text

        # 1. Figure caption paragraphs — apply blue to ALL runs
        if style_name == "figure caption":
            for r in p._element.iter(W + "r"):
                _set_run_color(r, BLUE)
            n_caps += 1
            continue

        # 2. Inline 'Fig. N' references in Body Text and Abstract
        if style_name not in ("Body Text", "Abstract"):
            continue
        m = FIG_INLINE_RE.search(text)
        if not m:
            continue
        # Only colour the FIRST inline match per paragraph (avoid run-split
        # complexity for paragraphs with multiple matches)
        _split_run_around_match(p._element, m.start(), m.end(), text)
        n_inlines += 1

    print(f"Figure caption paragraphs coloured blue: {n_caps}")
    print(f"Inline 'Fig. N' references coloured blue: {n_inlines}")

    doc.save(str(DOCX))
    print(f"\nSaved {DOCX.name}")


if __name__ == "__main__":
    main()
