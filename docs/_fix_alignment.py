"""Apply explicit paragraph-level formatting to match the JCM template
effective values, so the rendered output matches a Scopus-indexed-style
journal article regardless of style inheritance behaviour in different
Word versions.

For every paragraph in the article, this script sets explicit pPr/jc and
indent/spacing values that match the JCM template's resolved style defaults:

  Body Text         jc=both,      ind/firstLine=210
  Abstract          jc=both,      ind/firstLine=210
  references        jc=both
  figure caption    jc=center,    spacing/before=90, after=210, italic on runs
  Affiliation       jc=center
  Heading 1         jc=center,    bold + ALL CAPS on runs (IEEE convention)
  Heading 2         jc=left,      italic on runs
  Heading 5         jc=left,      bold italic on runs
  Style Author      jc=center,    spacing/after=120
  Style paper title jc=center,    bold on runs

This way every paragraph carries its alignment as an explicit pPr override,
not just an inherited style default — guaranteeing correct rendering in
Word, LibreOffice, and online Word viewers alike.
"""
from __future__ import annotations

from pathlib import Path

from docx import Document
from docx.oxml.ns import qn

DOCX = Path(__file__).parent / "pytestwaf-research-article.docx"
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _ensure_pPr(p_elem):
    pPr = p_elem.find(W + "pPr")
    if pPr is None:
        pPr = p_elem.makeelement(W + "pPr", {})
        p_elem.insert(0, pPr)
    return pPr


def _set_jc(p_elem, val):
    pPr = _ensure_pPr(p_elem)
    for jc in pPr.findall(W + "jc"):
        pPr.remove(jc)
    el = pPr.makeelement(W + "jc", {})
    el.set(qn("w:val"), val)
    pPr.append(el)


def _set_indent(p_elem, first_line=None, left=None, right=None):
    pPr = _ensure_pPr(p_elem)
    ind = pPr.find(W + "ind")
    if ind is None:
        ind = pPr.makeelement(W + "ind", {})
        pPr.append(ind)
    if first_line is not None:
        ind.set(qn("w:firstLine"), str(first_line))
    if left is not None:
        ind.set(qn("w:left"), str(left))
    if right is not None:
        ind.set(qn("w:right"), str(right))


def _set_spacing(p_elem, before=None, after=None, line=None, line_rule=None):
    pPr = _ensure_pPr(p_elem)
    sp = pPr.find(W + "spacing")
    if sp is None:
        sp = pPr.makeelement(W + "spacing", {})
        pPr.append(sp)
    if before is not None:
        sp.set(qn("w:before"), str(before))
    if after is not None:
        sp.set(qn("w:after"), str(after))
    if line is not None:
        sp.set(qn("w:line"), str(line))
    if line_rule is not None:
        sp.set(qn("w:lineRule"), line_rule)


def _set_run_bold(p, val: bool):
    for run in p.runs:
        run.bold = val


def _set_run_italic(p, val: bool):
    for run in p.runs:
        run.italic = val


def _set_run_caps(p, val: bool):
    """Use Word's small-caps via run-level rPr/caps (true caps display)."""
    for run in p.runs:
        rPr = run._element.get_or_add_rPr()
        existing = rPr.find(qn("w:caps"))
        if existing is not None:
            rPr.remove(existing)
        if val:
            el = rPr.makeelement(qn("w:caps"), {})
            el.set(qn("w:val"), "1")
            rPr.append(el)


def main():
    doc = Document(str(DOCX))

    counts = {
        "Body Text": 0, "Abstract": 0, "references": 0,
        "figure caption": 0, "Affiliation": 0,
        "Heading 1": 0, "Heading 2": 0, "Heading 5": 0,
        "Author": 0, "Title": 0, "other": 0,
    }

    for p in doc.paragraphs:
        sn = p.style.name
        elem = p._element

        # Body text and Abstract — JUSTIFIED with first-line indent (210 twips)
        if sn == "Body Text":
            # If this is a Consolas algorithm line (legacy from build), skip
            if any(r.font.name == "Consolas" for r in p.runs):
                continue
            _set_jc(elem, "both")
            _set_indent(elem, first_line=210)
            counts["Body Text"] += 1
        elif sn == "Abstract":
            _set_jc(elem, "both")
            _set_indent(elem, first_line=210)
            counts["Abstract"] += 1
        elif sn == "references":
            _set_jc(elem, "both")
            counts["references"] += 1

        # Figure captions — CENTERED with italic
        elif sn == "figure caption":
            _set_jc(elem, "center")
            _set_spacing(elem, before=90, after=210)
            counts["figure caption"] += 1

        # Affiliations — CENTERED
        elif sn == "Affiliation":
            _set_jc(elem, "center")
            counts["Affiliation"] += 1

        # Heading 1 — CENTERED + BOLD + CAPS (IEEE convention)
        elif sn == "Heading 1":
            _set_jc(elem, "center")
            _set_run_bold(p, True)
            _set_run_caps(p, True)
            counts["Heading 1"] += 1

        # Heading 2 — LEFT + ITALIC + BOLD (IEEE A./B./C.)
        elif sn == "Heading 2":
            _set_jc(elem, "left")
            _set_run_italic(p, True)
            _set_run_bold(p, True)
            counts["Heading 2"] += 1

        # Heading 5 — LEFT + BOLD + ITALIC (Conflict / Contributions / References)
        elif sn == "Heading 5":
            _set_jc(elem, "left")
            _set_run_bold(p, True)
            _set_run_italic(p, True)
            counts["Heading 5"] += 1

        # Author + Title — CENTERED, with explicit spacing
        elif "Author" in sn and "Heading" not in sn:
            _set_jc(elem, "center")
            _set_spacing(elem, before=0, after=120)
            counts["Author"] += 1
        elif "paper title" in sn.lower():
            _set_jc(elem, "center")
            _set_spacing(elem, before=120, after=120)
            _set_run_bold(p, True)
            counts["Title"] += 1
        else:
            counts["other"] += 1

    # Justify table cell paragraphs as well (cells often default to left in Word)
    for tbl in doc.tables:
        for row_i, row in enumerate(tbl.rows):
            for cell in row.cells:
                for cp in cell.paragraphs:
                    if not cp.text.strip():
                        continue
                    if row_i == 0:
                        # Header row — center + bold
                        _set_jc(cp._element, "center")
                        _set_run_bold(cp, True)
                    else:
                        _set_jc(cp._element, "left")

    print("Applied explicit JCM-matching formatting:")
    for k, v in counts.items():
        if v > 0:
            print(f"  {k:<20} {v:>4} paragraphs")

    doc.save(str(DOCX))
    print(f"\nSaved {DOCX.name}")


if __name__ == "__main__":
    main()
