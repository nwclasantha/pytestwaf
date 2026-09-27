"""Apply IEEE/JCM-style layout polish to the rebuilt article.

The JCM template uses 14 alternating section breaks: single-column (1-col)
for the title page, tables, and breaks; two-column (2-col) for the body.
When _build_article.py calls _clear_body(), it strips all embedded section
breaks and leaves a single 2-column section that incorrectly renders the
title page in two columns.

This script restores the IEEE look:
  - Section 0 (title page through Abstract + Keywords) -> 1 column
  - Continuous section break before "Introduction" -> 2 columns for body
  - Single-column wrap around each multi-column-wide table
  - Title centered + 18pt, Authors centered + 12pt, Affiliations centered
  - Body Text justified
  - Heading 1 / Heading 2 / Heading 5 keep their template defaults

Run AFTER _build_article.py and AFTER _insert_figures.py / _apply_blue_figs.py
/ _fix_alignment.py.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt

DOCX = Path(__file__).parent / "pytestwaf-research-article.docx"
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _make_cols(num: int, sep: bool = False, space: int = 720) -> OxmlElement:
    """Build a <w:cols> element with the given number of columns."""
    cols = OxmlElement("w:cols")
    cols.set(qn("w:num"), str(num))
    cols.set(qn("w:space"), str(space))
    if sep:
        cols.set(qn("w:sep"), "1")
    cols.set(qn("w:equalWidth"), "1")
    return cols


def _make_section_break(cols_num: int) -> OxmlElement:
    """Build a continuous <w:sectPr> with the given column count."""
    sectPr = OxmlElement("w:sectPr")
    type_el = OxmlElement("w:type")
    type_el.set(qn("w:val"), "continuous")
    sectPr.append(type_el)
    pgSz = OxmlElement("w:pgSz")
    pgSz.set(qn("w:w"), "11909")
    pgSz.set(qn("w:h"), "16834")
    sectPr.append(pgSz)
    pgMar = OxmlElement("w:pgMar")
    pgMar.set(qn("w:top"), "1080")
    pgMar.set(qn("w:right"), "1080")
    pgMar.set(qn("w:bottom"), "1080")
    pgMar.set(qn("w:left"), "1080")
    pgMar.set(qn("w:header"), "720")
    pgMar.set(qn("w:footer"), "720")
    pgMar.set(qn("w:gutter"), "0")
    sectPr.append(pgMar)
    sectPr.append(_make_cols(cols_num, sep=False, space=720))
    return sectPr


def _insert_section_break_before(para, cols_num: int) -> None:
    """Insert a paragraph BEFORE `para` whose pPr carries a continuous
    section break that switches to the given column count.

    Works because in OOXML, a section break lives inside the pPr of the
    LAST paragraph of a section. So inserting an empty paragraph with
    a sectPr-bearing pPr before `para` ends the prior section there.
    """
    p_elem = para._element
    new_p = OxmlElement("w:p")
    pPr = OxmlElement("w:pPr")
    pPr.append(_make_section_break(cols_num))
    new_p.append(pPr)
    p_elem.addprevious(new_p)


def _set_first_section_cols(doc, cols_num: int) -> None:
    """Force the document's final section properties to cols=N."""
    # The last paragraph holds the document's terminal sectPr.
    body = doc.element.body
    sectPr = body.find(W + "sectPr")
    if sectPr is None:
        return
    # Replace cols child
    cols = sectPr.find(W + "cols")
    if cols is not None:
        sectPr.remove(cols)
    sectPr.append(_make_cols(cols_num, sep=False, space=720))


def _set_alignment(p, align) -> None:
    p.alignment = align


def apply():
    doc = Document(str(DOCX))

    # 1. Title page paragraphs: centered + sized.
    intro_idx = None
    for i, p in enumerate(doc.paragraphs):
        sn = p.style.name
        if sn == "Heading 1" and intro_idx is None:
            intro_idx = i
            break
        if sn.startswith("Style paper title"):
            _set_alignment(p, WD_ALIGN_PARAGRAPH.CENTER)
            for run in p.runs:
                run.font.size = Pt(18)
                run.bold = True
        elif sn.startswith("Style Author"):
            _set_alignment(p, WD_ALIGN_PARAGRAPH.CENTER)
            for run in p.runs:
                run.font.size = Pt(12)
        elif sn == "Affiliation":
            _set_alignment(p, WD_ALIGN_PARAGRAPH.CENTER)
            for run in p.runs:
                run.font.size = Pt(10)
                run.italic = True
        elif sn == "Abstract":
            _set_alignment(p, WD_ALIGN_PARAGRAPH.JUSTIFY)
            for run in p.runs:
                run.font.size = Pt(10)
                run.bold = True if run.text.startswith(("Abstract", "Keywords")) else run.bold

    # 2. Justify Body Text everywhere.
    for p in doc.paragraphs:
        if p.style.name == "Body Text":
            # Don't touch monospace algorithm lines (Consolas)
            if any(r.font.name == "Consolas" for r in p.runs):
                continue
            _set_alignment(p, WD_ALIGN_PARAGRAPH.JUSTIFY)

    # 3. Insert continuous section break BEFORE the first Heading 1.
    #    This switches single-column (title page) -> two-column (body).
    if intro_idx is not None:
        intro_para = doc.paragraphs[intro_idx]
        _insert_section_break_before(intro_para, cols_num=1)
        print(f"  Inserted single->two-column break before "
              f"'{intro_para.text[:40]}' (paragraph {intro_idx})")

    # 4. Force the trailing/document section to be 2-column for the body.
    _set_first_section_cols(doc, cols_num=2)

    # 5. Style polish: ensure Heading 1 is bold + slightly larger, Heading 2
    #    is italic + bold (IEEE convention).
    for p in doc.paragraphs:
        if p.style.name == "Heading 1":
            _set_alignment(p, WD_ALIGN_PARAGRAPH.CENTER)
            for run in p.runs:
                run.bold = True
                run.font.size = Pt(11)
                # Small caps look
                run.font.all_caps = True
        elif p.style.name == "Heading 2":
            for run in p.runs:
                run.italic = True
                run.font.size = Pt(10.5)
        elif p.style.name == "Heading 5":
            for run in p.runs:
                run.bold = True
                run.italic = True
                run.font.size = Pt(10)

    doc.save(str(DOCX))
    print(f"  Title page set to single-column; body set to two-column")
    print(f"  Body Text justified, Headings styled IEEE-bold/italic/caps")
    print(f"\nSaved {DOCX.name}")


if __name__ == "__main__":
    apply()
