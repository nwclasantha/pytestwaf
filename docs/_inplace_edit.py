"""In-place edit JCM-20514-v5-fixed.docx → pytestwaf-research-article.docx.

Walks the template paragraph by paragraph and substitutes each text run with
the corresponding pytestwaf content, preserving every aspect of formatting:
  - 14 alternating 1-col / 2-col IEEE sections
  - Title / Author / Affiliation / Abstract / Heading 1-2-5 styles
  - Table cell formatting (4 tables)
  - Figure caption + references styles
  - Run-level fonts, sizes, italics, indentation

After the in-place text substitution, all 13 figure images are inserted
immediately before each 'Fig. N.' caption.
"""
from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Inches
from docx.text.paragraph import Paragraph

# Reuse content from the build script
from _build_article import (
    TITLE, AUTHORS, AFFILIATIONS, ABSTRACT, KEYWORDS,
    INTRO, BACKGROUND,
    LITREVIEW_INTRO, LITREVIEW_A, LITREVIEW_B,
    LIMITATIONS_INTRO, LIMITATIONS_A,
    PROPOSED_INTRO, PROPOSED_ALGO, PROPOSED_HYBRID, PROPOSED_CORPUS,
    PROPOSED_CLASSIFY, PROPOSED_ENGINE, PROPOSED_MUTATION, PROPOSED_PERSIST,
    EXP_INTRO, EXP_REALTIME, EXP_CONTINUOUS, EXP_HYBRID, EXP_AUTOFIX,
    EXP_TRAINING, EXP_DATASET, EXP_TRAINARCH,
    RES_INTRO, RES_OVERALL, RES_COMPARE, RES_LEARN, RES_ADAPT, RES_METRICS,
    DISCUSSION, ETHICS, CONCLUSIONS,
    CONFLICT, CONTRIBUTIONS, REFERENCES,
    TABLE_I, TABLE_II, TABLE_III, TABLE_IV,
)

TEMPLATE = Path(__file__).parent / "JCM-20514-v5-fixed.docx"
OUTPUT = Path(__file__).parent / "pytestwaf-research-article.docx"
DIAGRAMS = Path(__file__).parent / "diagrams"
PPTX_IMG = Path(__file__).parent / "pptx_extracted"


# ---------- ordered tapes by style ----------------------------------------

# Title row (one paragraph in template)
TITLE_TAPE = [TITLE]

# Author row (one paragraph)
AUTHOR_TAPE = [AUTHORS]

# Affiliations (5 paragraphs in template)
AFFIL_TAPE = list(AFFILIATIONS)

# Abstract (template has 4 'Abstract'-styled paragraphs incl. blanks; first
# substantive one is the abstract, last substantive one is keywords)
ABSTRACT_TAPE = [ABSTRACT, "", KEYWORDS, ""]

# Heading 1 — 10 items in document order
H1_TAPE = [
    "Introduction",
    "Background",
    "Literature Review",
    "Limitations of Existing WAF Validation Architectures",
    "Methodology",
    "Experimental Design",
    "Results",
    "Discussion",
    "Ethical Considerations and Data Privacy",
    "Conclusions",
]

# Heading 2 — 22 items in document order (matches template count).
# Section V's H2 entries are explicitly phase-prefixed so a reader sees the
# nine pytestwaf phases (Input -> Pre-flight -> Scan -> Classify -> Learn ->
# Attack-again -> Generate-fixes -> Report -> Remember) mapped onto
# subsection labels.
H2_TAPE = [
    "A. Overview of WAF Validation Research",
    "B. Real-World Case Studies for WAF Bypass Detection",
    "A. Comparative Analysis of Existing Approaches",
    "A. End-to-End Algorithm and Phase Map",
    "A. Phase 1-2: Input Configuration and Pre-Flight Discovery",
    "B. Phase 3: Test Corpus Construction",
    "C. Phase 4: Four-Layer Response Classification Pipeline",
    "D. Phase 5: Hybrid ML Engine and In-Flight Training",
    "E. Phase 6: Adaptive Mutation Engine",
    "F. Phases 7, 8 and 9: Auto-Remediation, Reporting, and Cross-Scan Persistence",
    "A. Real-Time Bypass Detection and Cross-Layer Classification",
    "B. Continuous Payload Generation",
    "C. Hybrid ML Engine for Automated Bypass Scoring",
    "D. Auto-Remediation Generation Pipeline",
    "E. Hybrid ML Model Training and Optimisation",
    "F. Dataset",
    "G. Hybrid ML Training Architecture",
    "A. Overall Hybrid ML Predictions on the Production WAF Target",
    "B. Hybrid Supervised ML Models Comparison",
    "C. Learning Curve Analysis",
    "D. Hybrid ML-Driven Adaptive Mutation Effectiveness",
    "E. Definitions of Hybrid ML Classification Metrics",
]

# Heading 5 — 3 items at the tail
H5_TAPE = ["Conflict of Interest", "Author Contributions", "References"]

# References — 33 items
REF_TAPE = [f"[{i+1}] {r}" for i, r in enumerate(REFERENCES)]

# Figure captions — full document order
FIG_TAPE = [
    "Fig. 1. Algorithm of proposed hybrid ML-based WAF validation.",
    "Fig. 2. Hybrid WAF validation methodology.",
    "Fig. 3. Four-layer response classification pipeline.",
    "Fig. 4. Experimental architecture and deployment topology.",
    "Fig. 5. Hybrid ML training architecture.",
    "Fig. 6. Hybrid ML prediction architecture.",
    "Fig. 7. Hybrid ML predictions on multiple WAF targets.",
    "Fig. 8. Hybrid supervised ML models comparison.",
    "Fig. 9. LR learning curve behaviour.",
    "Fig. 10. KNN learning curve behaviour.",
    "Fig. 11. RF learning curve behaviour.",
    "Fig. 12. SVC learning curve behaviour.",
    "Fig. 13. GB learning curve behaviour.",
    "Fig. 20. Block / Bypass distribution by encoder.",
    "Fig. 21. Block / Bypass distribution by placeholder.",
    "Fig. 22. Encoder x placeholder bypass-rate heat map (top 15).",
    "Fig. 23. Attack-type composition of bypass candidates.",
    "Fig. 24. Top-risk bypass candidates ranked by calibrated probability.",
    "Fig. 25. MITRE ATT&CK coverage by attack category.",
    "Fig. 26. Cyber kill-chain coverage of blocked and bypassed payloads.",
    "Fig. 27. MITRE tactic coverage radar (detection rate, per cent).",
]

# Body text content — appended in document order. Each Body Text paragraph
# slot in the template will pop one item from the front of this tape.
# Special items starting with "TABLE " or "Fig. " will replace the
# corresponding originals (template uses Body Text style for table refs and
# fig refs alike).

def _strip_algo(items: list[str]) -> list[str]:
    """Remove ALGOTITLE|/ALGO| pseudocode lines.

    The JCM template's Proposed Solution section has a fixed number of
    Body Text slots; flooding them with 50+ monospace algorithm lines
    pushes descriptive subsection content (V.A Hybrid ML-Driven, V.B Test
    Corpus, etc.) out of their proper slots. We render the algorithm via
    Fig. 1 instead, so the pseudocode is redundant in this path.
    """
    return [s for s in items
            if not s.startswith("ALGO|") and not s.startswith("ALGOTITLE|")]


BODY_TAPE: list[str] = []
# Section 1: Introduction
BODY_TAPE += INTRO
# Section 2: Background
BODY_TAPE += BACKGROUND
# Section 3: Literature Review
BODY_TAPE += LITREVIEW_INTRO
BODY_TAPE += LITREVIEW_A   # contains "TABLE I.", "TABLE II." captions
BODY_TAPE += LITREVIEW_B
# Section 4: Limitations
BODY_TAPE += LIMITATIONS_INTRO
BODY_TAPE += LIMITATIONS_A  # contains "TABLE III." caption
# Section 5: Proposed Solution
BODY_TAPE += PROPOSED_INTRO
BODY_TAPE += PROPOSED_ALGO       # contains Fig. 1, Fig. 2 captions
BODY_TAPE += PROPOSED_HYBRID
BODY_TAPE += PROPOSED_CORPUS
BODY_TAPE += PROPOSED_CLASSIFY   # contains Fig. 3 caption
BODY_TAPE += PROPOSED_ENGINE
BODY_TAPE += PROPOSED_MUTATION
BODY_TAPE += PROPOSED_PERSIST
# Section 6: Experimental Design
BODY_TAPE += EXP_INTRO           # contains Fig. 4 caption
BODY_TAPE += EXP_REALTIME
BODY_TAPE += EXP_CONTINUOUS
BODY_TAPE += EXP_HYBRID
BODY_TAPE += EXP_AUTOFIX
BODY_TAPE += EXP_TRAINING
BODY_TAPE += EXP_DATASET         # contains "TABLE IV." caption
BODY_TAPE += EXP_TRAINARCH       # contains Fig. 5, Fig. 6 captions
# Section 7: Results
BODY_TAPE += RES_INTRO
BODY_TAPE += RES_OVERALL         # contains Fig. 7 caption
BODY_TAPE += RES_COMPARE         # contains Fig. 8 caption
BODY_TAPE += RES_LEARN           # contains Fig. 9-13 captions
BODY_TAPE += RES_ADAPT
BODY_TAPE += RES_METRICS
# Section 8: Discussion
BODY_TAPE += DISCUSSION
# Section 9: Ethics
BODY_TAPE += ETHICS
# Section 10: Conclusions
BODY_TAPE += CONCLUSIONS
# Conflict of Interest body (1 paragraph)
BODY_TAPE += [CONFLICT]
# Author Contributions body (1 paragraph)
BODY_TAPE += [CONTRIBUTIONS]


# Section-keyed body content: maps Heading 1 text → list of body paragraphs
# expected to live in that section. Used as fallback for sections without H2
# subsections (Introduction, Background, Discussion, Ethics, Conclusions).
BODY_BY_SECTION: dict[str, list[str]] = {
    "Introduction":                                                _strip_algo(INTRO),
    "Background":                                                  _strip_algo(BACKGROUND),
    "Discussion":                                                  _strip_algo(DISCUSSION),
    "Ethical Considerations and Data Privacy":                     _strip_algo(ETHICS),
    "Conclusions":                                                 _strip_algo(CONCLUSIONS),
}

# Section-intro content rendered between H1 and the first H2 (for sections
# that have H2 subsections).
H1_INTRO_BY_SECTION: dict[str, list[str]] = {
    "Literature Review":                                           _strip_algo(LITREVIEW_INTRO),
    "Limitations of Existing WAF Validation Architectures":        _strip_algo(LIMITATIONS_INTRO),
    "Methodology":                                                 _strip_algo(PROPOSED_INTRO),
    "Experimental Design":                                         _strip_algo(EXP_INTRO),
    "Results":                                                     _strip_algo(RES_INTRO),
}

# Per-H2 body content. Each H2 subsection text maps to its own body paragraph
# list. The walk pops from the current H2's queue whenever it encounters a
# Body Text slot in the template. Residue is drained right before the next
# H2 (or H1 if no further H2). This keeps content under its proper subsection.
BODY_BY_H2: dict[str, list[str]] = {
    "A. Overview of WAF Validation Research":                              _strip_algo(LITREVIEW_A),
    "B. Real-World Case Studies for WAF Bypass Detection":                 _strip_algo(LITREVIEW_B),
    "A. Comparative Analysis of Existing Approaches":                      _strip_algo(LIMITATIONS_A),
    "A. End-to-End Algorithm and Phase Map":                               _strip_algo(PROPOSED_ALGO),
    "A. Phase 1-2: Input Configuration and Pre-Flight Discovery":          _strip_algo(PROPOSED_HYBRID),
    "B. Phase 3: Test Corpus Construction":                                _strip_algo(PROPOSED_CORPUS),
    "C. Phase 4: Four-Layer Response Classification Pipeline":             _strip_algo(PROPOSED_CLASSIFY),
    "D. Phase 5: Hybrid ML Engine and In-Flight Training":                 _strip_algo(PROPOSED_ENGINE),
    "E. Phase 6: Adaptive Mutation Engine":                                _strip_algo(PROPOSED_MUTATION),
    "F. Phases 7, 8 and 9: Auto-Remediation, Reporting, and Cross-Scan Persistence": _strip_algo(PROPOSED_PERSIST),
    "A. Real-Time Bypass Detection and Cross-Layer Classification":        _strip_algo(EXP_REALTIME),
    "B. Continuous Payload Generation":                                    _strip_algo(EXP_CONTINUOUS),
    "C. Hybrid ML Engine for Automated Bypass Scoring":                    _strip_algo(EXP_HYBRID),
    "D. Auto-Remediation Generation Pipeline":                             _strip_algo(EXP_AUTOFIX),
    "E. Hybrid ML Model Training and Optimisation":                        _strip_algo(EXP_TRAINING),
    "F. Dataset":                                                          _strip_algo(EXP_DATASET),
    "G. Hybrid ML Training Architecture":                                  _strip_algo(EXP_TRAINARCH),
    "A. Overall Hybrid ML Predictions on the Production WAF Target":       _strip_algo(RES_OVERALL),
    "B. Hybrid Supervised ML Models Comparison":                           _strip_algo(RES_COMPARE),
    "C. Learning Curve Analysis":                                          _strip_algo(RES_LEARN),
    "D. Hybrid ML-Driven Adaptive Mutation Effectiveness":                 _strip_algo(RES_ADAPT),
    "E. Definitions of Hybrid ML Classification Metrics":                  _strip_algo(RES_METRICS),
}


# ---------- helpers --------------------------------------------------------

def replace_text(p, new_text: str) -> None:
    """Replace a paragraph's text while preserving the first run's
    formatting. All other runs are emptied so re-flow happens through
    the first run.

    Special prefixes:
      "ALGOTITLE|<text>" -> bold text on the first run
      "ALGO|<text>"      -> Consolas 9pt monospace on the first run
                            (algorithm pseudocode lines)
    """
    is_algo_title = new_text.startswith("ALGOTITLE|")
    is_algo_line = new_text.startswith("ALGO|") and not is_algo_title
    if is_algo_title:
        new_text = new_text[len("ALGOTITLE|"):]
    elif is_algo_line:
        new_text = new_text[len("ALGO|"):]

    runs = p.runs
    if not runs:
        p.add_run(new_text)
        runs = p.runs
    else:
        runs[0].text = new_text
        for r in runs[1:]:
            r.text = ""

    if is_algo_title and runs:
        runs[0].bold = True
    elif is_algo_line and runs:
        run = runs[0]
        run.font.name = "Consolas"
        from docx.shared import Pt as _Pt
        run.font.size = _Pt(9)
        rPr = run._element.get_or_add_rPr()
        rFonts = rPr.find(qn("w:rFonts"))
        if rFonts is None:
            from docx.oxml import OxmlElement as _OxmlElement
            rFonts = _OxmlElement("w:rFonts")
            rPr.append(rFonts)
        rFonts.set(qn("w:ascii"), "Consolas")
        rFonts.set(qn("w:hAnsi"), "Consolas")
        rFonts.set(qn("w:cs"), "Consolas")


FIG_REF_RE = re.compile(r"\b(Figs?\.\s+)(\d+)")
FIG_RANGE_RE = re.compile(
    r"\bFigs\.\s+(\d+)\s+(through|to|-|–)\s+(\d+)"
)


def _renumber_figure_references(doc) -> dict[int, int]:
    """Renumber figure captions and in-text Fig./Figs. references according
    to the actual caption order in the generated document."""
    cap_re = re.compile(r"^Fig\.\s+(\d+)\.\s")
    old_order: list[int] = []
    for p in doc.paragraphs:
        if p.style.name != "figure caption":
            continue
        m = cap_re.match(p.text.strip())
        if not m:
            continue
        n = int(m.group(1))
        if n not in old_order:
            old_order.append(n)

    mapping = {old: new for new, old in enumerate(old_order, start=1)}
    if all(old == new for old, new in mapping.items()):
        return mapping

    def repl_text(text: str) -> str:
        def repl_range(m: re.Match) -> str:
            start = int(m.group(1))
            sep = m.group(2)
            end = int(m.group(3))
            return f"Figs. {mapping.get(start, start)} {sep} {mapping.get(end, end)}"

        def repl_single(m: re.Match) -> str:
            n = int(m.group(2))
            return f"{m.group(1)}{mapping.get(n, n)}"

        text = FIG_RANGE_RE.sub(repl_range, text)
        return FIG_REF_RE.sub(repl_single, text)

    paragraphs = list(doc.paragraphs)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                paragraphs.extend(cell.paragraphs)

    changed = 0
    for p in paragraphs:
        old_text = p.text
        if "Fig" not in old_text:
            continue
        new_text = repl_text(old_text)
        if new_text != old_text:
            replace_text(p, new_text)
            changed += 1

    print(f"Renumbered figure references in {changed} paragraphs")
    print("Figure renumber map:", mapping)
    return mapping


def _make_section_break(cols_num: int):
    """Build a continuous <w:sectPr> with the given column count, matching
    the JCM template's page-size and margins."""
    from docx.oxml import OxmlElement as _OxmlElement
    sectPr = _OxmlElement("w:sectPr")
    type_el = _OxmlElement("w:type")
    type_el.set(qn("w:val"), "continuous")
    sectPr.append(type_el)
    pgSz = _OxmlElement("w:pgSz")
    pgSz.set(qn("w:w"), "11909")
    pgSz.set(qn("w:h"), "16834")
    sectPr.append(pgSz)
    pgMar = _OxmlElement("w:pgMar")
    # Match the JCM template section geometry exactly. Earlier generated
    # full-width figure sections used 0.75" margins and 720 twip column
    # spacing, which made the article drift from the reference format.
    pgMar.set(qn("w:top"), "1701")
    pgMar.set(qn("w:right"), "1134")
    pgMar.set(qn("w:bottom"), "1134")
    pgMar.set(qn("w:left"), "1134")
    pgMar.set(qn("w:header"), "720")
    pgMar.set(qn("w:footer"), "720")
    pgMar.set(qn("w:gutter"), "0")
    sectPr.append(pgMar)
    cols = _OxmlElement("w:cols")
    cols.set(qn("w:num"), str(cols_num))
    cols.set(qn("w:space"), "340")
    sectPr.append(cols)
    return sectPr


def _insert_section_break_before(target_para, cols_num: int):
    """Insert an empty paragraph BEFORE target_para whose pPr carries a
    continuous section break that switches to the given column count."""
    from docx.oxml import OxmlElement as _OxmlElement
    new_p = _OxmlElement("w:p")
    pPr = _OxmlElement("w:pPr")
    pPr.append(_make_section_break(cols_num))
    new_p.append(pPr)
    target_para._element.addprevious(new_p)


def insert_picture_before(target_para, image_path: Path, width_in: float,
                          full_width: bool = False):
    """Insert a centered image as a new paragraph immediately before
    target_para. If full_width=True, wrap the image+caption in a
    1-column section break so the figure spans the full page width
    (IEEE figure* pattern), then return to 2-column for the body that
    follows the caption."""
    if full_width:
        # 1) section break -> 1-column BEFORE the image
        _insert_section_break_before(target_para, cols_num=1)
        # 2) image paragraph
        new_p_el = target_para._element.makeelement(qn("w:p"), {})
        target_para._element.addprevious(new_p_el)
        new_para = Paragraph(new_p_el, target_para._parent)
        new_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = new_para.add_run()
        run.add_picture(str(image_path), width=Inches(width_in))
        # 3) target_para is the caption — leave it in the 1-col section.
        # 4) section break AFTER the caption to return to 2-column for the
        #    body paragraphs that follow. Insert AFTER target_para.
        from docx.oxml import OxmlElement as _OxmlElement
        next_p = _OxmlElement("w:p")
        next_pPr = _OxmlElement("w:pPr")
        next_pPr.append(_make_section_break(2))
        next_p.append(next_pPr)
        target_para._element.addnext(next_p)
        return

    # Default: in-column figure
    new_p_el = target_para._element.makeelement(qn("w:p"), {})
    target_para._element.addprevious(new_p_el)
    new_para = Paragraph(new_p_el, target_para._parent)
    new_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = new_para.add_run()
    run.add_picture(str(image_path), width=Inches(width_in))


def _clone_paragraph_before(template_para: Paragraph, text: str) -> Paragraph:
    """Clone template_para's XML, replace its text, insert before it.
    Cloning preserves every aspect of formatting (style, run-properties,
    indentation, paragraph-properties)."""
    new_el = deepcopy(template_para._element)
    # Strip all existing text and runs except the FIRST run, which we
    # repurpose as the formatting carrier for the new text.
    runs = new_el.findall(qn("w:r"))
    if runs:
        # Clear text in all runs
        for r in runs:
            for t in r.findall(qn("w:t")):
                r.remove(t)
        # Add new text to first run
        new_t = new_el.makeelement(qn("w:t"), {})
        new_t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        new_t.text = text
        runs[0].append(new_t)
        # Remove all runs after the first
        for extra in runs[1:]:
            new_el.remove(extra)
    template_para._element.addprevious(new_el)
    return Paragraph(new_el, template_para._parent)


def _clone_paragraph_after(template_para: Paragraph, text: str) -> Paragraph:
    """Clone template_para and insert immediately AFTER it."""
    new_el = deepcopy(template_para._element)
    runs = new_el.findall(qn("w:r"))
    if runs:
        for r in runs:
            for t in r.findall(qn("w:t")):
                r.remove(t)
        new_t = new_el.makeelement(qn("w:t"), {})
        new_t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        new_t.text = text
        runs[0].append(new_t)
        for extra in runs[1:]:
            new_el.remove(extra)
    template_para._element.addnext(new_el)
    return Paragraph(new_el, template_para._parent)


def _drain_residue_before(next_h1_para: Paragraph,
                          section_name: str,
                          body_queues: dict,
                          last_body_para_in_section: dict) -> None:
    """If section_name's body queue still has items, insert them right
    before next_h1_para. Each new paragraph clones the LAST consumed
    Body Text paragraph of that section (preserving its style + run
    formatting) and is inserted at next_h1_para's location.
    """
    q = body_queues.get(section_name, [])
    if not q:
        return
    body_template = last_body_para_in_section.get(section_name)
    if body_template is None:
        # No body text was consumed in this section — fall back to a
        # newly-styled paragraph (style attribute set explicitly).
        from docx.oxml.ns import qn as _qn
        for text in q:
            # Clone the H1 element only as an XML carrier, then re-style it
            new_el = deepcopy(next_h1_para._element)
            # Replace pStyle with Body Text
            pPr = new_el.find(_qn("w:pPr"))
            if pPr is not None:
                pStyle = pPr.find(_qn("w:pStyle"))
                if pStyle is not None:
                    pStyle.set(_qn("w:val"), "BodyText")
            # Strip runs and set new text
            for r in new_el.findall(_qn("w:r")):
                new_el.remove(r)
            new_r = new_el.makeelement(_qn("w:r"), {})
            new_t = new_el.makeelement(_qn("w:t"), {})
            new_t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            new_t.text = text
            new_r.append(new_t)
            new_el.append(new_r)
            next_h1_para._element.addprevious(new_el)
        body_queues[section_name] = []
        return
    # Clone the last body text paragraph of this section as the template,
    # placing each residue item right before next_h1_para.
    for text in q:
        new_el = deepcopy(body_template._element)
        runs = new_el.findall(qn("w:r"))
        if runs:
            for r in runs:
                for t in r.findall(qn("w:t")):
                    r.remove(t)
            new_t = new_el.makeelement(qn("w:t"), {})
            new_t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            new_t.text = text
            runs[0].append(new_t)
            for extra in runs[1:]:
                new_el.remove(extra)
        next_h1_para._element.addprevious(new_el)
    body_queues[section_name] = []


def _append_residue_after(anchor_para: Paragraph,
                          section_name: str,
                          body_queues: dict) -> None:
    """Append the last section's residue right AFTER its last existing
    Body Text paragraph (preserves Body Text style via deepcopy)."""
    q = body_queues.get(section_name, [])
    if not q:
        return
    cur = anchor_para
    for text in q:
        new_el = deepcopy(cur._element)
        runs = new_el.findall(qn("w:r"))
        if runs:
            for r in runs:
                for t in r.findall(qn("w:t")):
                    r.remove(t)
            new_t = new_el.makeelement(qn("w:t"), {})
            new_t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            new_t.text = text
            runs[0].append(new_t)
            for extra in runs[1:]:
                new_el.remove(extra)
        cur._element.addnext(new_el)
        # Update cur to point to the newly inserted element
        cur = Paragraph(new_el, cur._parent)
    body_queues[section_name] = []


# ---------- main edit pass -------------------------------------------------

def edit_in_place():
    doc = Document(str(TEMPLATE))

    # Per-style FIFO queues for everything EXCEPT Body Text.
    queues = {
        "Title": list(TITLE_TAPE),
        "Author": list(AUTHOR_TAPE),
        "Affiliation": list(AFFIL_TAPE),
        "Abstract": list(ABSTRACT_TAPE),
        "Heading 1": list(H1_TAPE),
        "Heading 2": list(H2_TAPE),
        "Heading 5": list(H5_TAPE),
        "references": list(REF_TAPE),
        "figure caption": list(FIG_TAPE),
    }

    # Body Text routing:
    #   - For sections WITHOUT H2 subsections: per-H1 queue (BODY_BY_SECTION)
    #   - For sections WITH H2 subsections: per-H2 queue (BODY_BY_H2),
    #     plus a section-intro queue (H1_INTRO_BY_SECTION) for the body
    #     paragraphs that appear between H1 and the first H2.
    body_h1_queues: dict[str, list[str]] = {k: list(v) for k, v in BODY_BY_SECTION.items()}
    body_h1_intro_queues: dict[str, list[str]] = {k: list(v) for k, v in H1_INTRO_BY_SECTION.items()}
    body_h2_queues: dict[str, list[str]] = {k: list(v) for k, v in BODY_BY_H2.items()}

    current_h1: str | None = None
    current_h2: str | None = None
    last_body_in_h1: dict[str, "object"] = {}
    last_body_in_h2: dict[str, "object"] = {}
    last_body_in_h1_intro: dict[str, "object"] = {}

    def _drain_h2(target_para):
        """Drain residue of current_h2's queue right BEFORE target_para."""
        if not current_h2:
            return
        q = body_h2_queues.get(current_h2, [])
        if not q:
            return
        anchor = last_body_in_h2.get(current_h2)
        if anchor is None:
            # No body slot was used for this H2 — fabricate a paragraph by
            # cloning the H2 paragraph's element and re-styling to Body Text.
            from docx.oxml.ns import qn as _qn
            for text in q:
                new_el = deepcopy(target_para._element)
                pPr = new_el.find(_qn("w:pPr"))
                if pPr is not None:
                    pStyle = pPr.find(_qn("w:pStyle"))
                    if pStyle is not None:
                        pStyle.set(_qn("w:val"), "BodyText")
                for r in new_el.findall(_qn("w:r")):
                    new_el.remove(r)
                new_r = new_el.makeelement(_qn("w:r"), {})
                new_t = new_el.makeelement(_qn("w:t"), {})
                new_t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
                new_t.text = text
                new_r.append(new_t)
                new_el.append(new_r)
                target_para._element.addprevious(new_el)
            body_h2_queues[current_h2] = []
            return
        # Clone the last consumed body paragraph as the formatting template,
        # insert each residue item right before target_para.
        for text in q:
            new_el = deepcopy(anchor._element)
            runs = new_el.findall(qn("w:r"))
            if runs:
                for r in runs:
                    for t in r.findall(qn("w:t")):
                        r.remove(t)
                new_t = new_el.makeelement(qn("w:t"), {})
                new_t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
                new_t.text = text
                runs[0].append(new_t)
                for extra in runs[1:]:
                    new_el.remove(extra)
            target_para._element.addprevious(new_el)
        body_h2_queues[current_h2] = []

    def _drain_h1_intro(target_para):
        """Drain residue of current_h1's intro queue (paragraphs between H1
        and the first H2) right BEFORE target_para. Used for sections with
        H2 subsections when the intro queue still has items."""
        if not current_h1:
            return
        q = body_h1_intro_queues.get(current_h1, [])
        if not q:
            return
        anchor = last_body_in_h1_intro.get(current_h1)
        # Same clone/fabricate strategy as _drain_h2
        for text in q:
            if anchor is None:
                from docx.oxml.ns import qn as _qn
                new_el = deepcopy(target_para._element)
                pPr = new_el.find(_qn("w:pPr"))
                if pPr is not None:
                    pStyle = pPr.find(_qn("w:pStyle"))
                    if pStyle is not None:
                        pStyle.set(_qn("w:val"), "BodyText")
                for r in new_el.findall(_qn("w:r")):
                    new_el.remove(r)
                new_r = new_el.makeelement(_qn("w:r"), {})
                new_t = new_el.makeelement(_qn("w:t"), {})
                new_t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
                new_t.text = text
                new_r.append(new_t)
                new_el.append(new_r)
                target_para._element.addprevious(new_el)
            else:
                new_el = deepcopy(anchor._element)
                runs = new_el.findall(qn("w:r"))
                if runs:
                    for r in runs:
                        for t in r.findall(qn("w:t")):
                            r.remove(t)
                    new_t = new_el.makeelement(qn("w:t"), {})
                    new_t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
                    new_t.text = text
                    runs[0].append(new_t)
                    for extra in runs[1:]:
                        new_el.remove(extra)
                target_para._element.addprevious(new_el)
        body_h1_intro_queues[current_h1] = []

    def _drain_h1(target_para):
        """Drain residue of current_h1's flat queue (sections with no H2)."""
        if not current_h1:
            return
        q = body_h1_queues.get(current_h1, [])
        if not q:
            return
        anchor = last_body_in_h1.get(current_h1)
        for text in q:
            if anchor is None:
                from docx.oxml.ns import qn as _qn
                new_el = deepcopy(target_para._element)
                pPr = new_el.find(_qn("w:pPr"))
                if pPr is not None:
                    pStyle = pPr.find(_qn("w:pStyle"))
                    if pStyle is not None:
                        pStyle.set(_qn("w:val"), "BodyText")
                for r in new_el.findall(_qn("w:r")):
                    new_el.remove(r)
                new_r = new_el.makeelement(_qn("w:r"), {})
                new_t = new_el.makeelement(_qn("w:t"), {})
                new_t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
                new_t.text = text
                new_r.append(new_t)
                new_el.append(new_r)
                target_para._element.addprevious(new_el)
            else:
                new_el = deepcopy(anchor._element)
                runs = new_el.findall(qn("w:r"))
                if runs:
                    for r in runs:
                        for t in r.findall(qn("w:t")):
                            r.remove(t)
                    new_t = new_el.makeelement(qn("w:t"), {})
                    new_t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
                    new_t.text = text
                    runs[0].append(new_t)
                    for extra in runs[1:]:
                        new_el.remove(extra)
                target_para._element.addprevious(new_el)
        body_h1_queues[current_h1] = []

    paragraphs = list(doc.paragraphs)
    for p in paragraphs:
        sname = p.style.name

        if "paper title" in sname.lower():
            key = "Title"
        elif "Author" in sname and "Heading" not in sname:
            key = "Author"
        elif sname == "Affiliation":
            key = "Affiliation"
        elif sname == "Abstract":
            key = "Abstract"
        elif sname in ("Heading 1", "Heading 2", "Heading 5",
                       "references", "figure caption", "Body Text"):
            key = sname
        else:
            continue

        if key == "Heading 1":
            # Drain residue of: current_h2 (if any) -> h1_intro (if any) -> h1 flat
            _drain_h2(p)
            _drain_h1_intro(p)
            _drain_h1(p)
            current_h2 = None
            q = queues[key]
            if q:
                new_h1 = q.pop(0)
                replace_text(p, new_h1)
                current_h1 = new_h1
            continue

        if key == "Heading 2":
            # Drain residue of previous H2; then drain h1_intro before this
            # first H2 (sections with H2 always have intro before first H2)
            _drain_h2(p)
            _drain_h1_intro(p)
            q = queues[key]
            if q:
                new_h2 = q.pop(0)
                replace_text(p, new_h2)
                current_h2 = new_h2
            continue

        if key == "Body Text":
            # Routing priority:
            #   1) current_h2's queue (if active and non-empty)
            #   2) current_h1's intro queue (if H2 not yet seen and intro exists)
            #   3) current_h1's flat queue (sections without H2)
            #   4) blank (no expected content)
            consumed = False
            if current_h2 and body_h2_queues.get(current_h2):
                replace_text(p, body_h2_queues[current_h2].pop(0))
                last_body_in_h2[current_h2] = p
                consumed = True
            elif (current_h1 and current_h2 is None
                  and body_h1_intro_queues.get(current_h1)):
                replace_text(p, body_h1_intro_queues[current_h1].pop(0))
                last_body_in_h1_intro[current_h1] = p
                consumed = True
            elif current_h1 and body_h1_queues.get(current_h1):
                replace_text(p, body_h1_queues[current_h1].pop(0))
                last_body_in_h1[current_h1] = p
                consumed = True
            if not consumed:
                replace_text(p, "")
            continue

        q = queues[key]
        if not q:
            replace_text(p, "")
            continue
        replace_text(p, q.pop(0))

    # After the walk: any residue must be appended at the end of the document.
    # Find the last paragraph as anchor.
    if paragraphs:
        # Drain any remaining H2 residue, h1 intro, h1 flat at end of doc.
        last_para = paragraphs[-1]
        # H2 residue
        if current_h2:
            q = body_h2_queues.get(current_h2, [])
            if q and last_body_in_h2.get(current_h2):
                _append_residue_after(
                    last_body_in_h2[current_h2], current_h2, body_h2_queues)
        # H1 residue
        if current_h1:
            q = body_h1_queues.get(current_h1, [])
            if q and last_body_in_h1.get(current_h1):
                _append_residue_after(
                    last_body_in_h1[current_h1], current_h1, body_h1_queues)

    # Report any residue left
    print("=== Queue residue (items not consumed) ===")
    for k, v in queues.items():
        if v:
            print(f"  {k}: {len(v)} items left")
    for h2, q in body_h2_queues.items():
        if q:
            print(f"  Body Text [H2: {h2}]: {len(q)} items left")
    for h1, q in body_h1_intro_queues.items():
        if q:
            print(f"  Body Text [H1 intro: {h1}]: {len(q)} items left")
    for h1, q in body_h1_queues.items():
        if q:
            print(f"  Body Text [H1: {h1}]: {len(q)} items left")

    # ---------- replace tables ----------
    new_tables = [TABLE_I, TABLE_II, TABLE_III, TABLE_IV]
    for orig_t, new_t in zip(doc.tables, new_tables):
        n_rows_old = len(orig_t.rows)
        n_cols_old = len(orig_t.columns)
        n_rows_new = len(new_t)
        n_cols_new = len(new_t[0])

        # Rewrite cells we have
        for r_i in range(min(n_rows_old, n_rows_new)):
            for c_i in range(min(n_cols_old, n_cols_new)):
                cell = orig_t.cell(r_i, c_i)
                # Clear all paragraph text in cell
                first = cell.paragraphs[0]
                replace_text(first, new_t[r_i][c_i])
                for extra in cell.paragraphs[1:]:
                    replace_text(extra, "")

        # If new table needs more rows, append — copy the last existing row
        # so formatting carries over.
        for r_i in range(n_rows_old, n_rows_new):
            new_row = orig_t.add_row()
            for c_i in range(min(n_cols_old, n_cols_new)):
                replace_text(new_row.cells[c_i].paragraphs[0], new_t[r_i][c_i])

        # If old table has surplus rows (we have fewer), blank them
        for r_i in range(n_rows_new, n_rows_old):
            for c_i in range(n_cols_old):
                cell = orig_t.cell(r_i, c_i)
                for p in cell.paragraphs:
                    replace_text(p, "")

    # ---------- insert figure images ----------
    # All figures are clean matplotlib block diagrams generated by
    # _build_arch_figures.py — no background patterns, large readable
    # 12-14pt fonts, grayscale fills with dark borders, no colour.
    fig_map = {
        1:  DIAGRAMS / "fig01_algorithm.png",           # Complete scan lifecycle (algorithm)
        2:  DIAGRAMS / "fig02_methodology.png",         # Hybrid WAF validation methodology
        3:  PPTX_IMG / "slide03.png",                   # Response Classification Pipeline
        4:  PPTX_IMG / "slide10.png",                   # Deployment topology
        5:  PPTX_IMG / "slide04.png",                   # ML training arch
        6:  PPTX_IMG / "slide05.png",                   # ML prediction / inference strategy
        7:  DIAGRAMS / "waf-ml-bypass-distribution.png",
        8:  DIAGRAMS / "waf-ml-confusion-matrix.png",
        9:  DIAGRAMS / "waf-ml-calibration-plot.png",
        10: DIAGRAMS / "waf-ml-per-class-prf.png",
        11: DIAGRAMS / "waf-ml-feature-importance.png",
        12: DIAGRAMS / "waf-ml-bypass-by-attack-type.png",
        13: DIAGRAMS / "waf-ml-class-balance.png",
        14: PPTX_IMG / "slide06.png",
        15: PPTX_IMG / "slide07.png",
        16: PPTX_IMG / "slide08.png",
        17: PPTX_IMG / "slide09.png",
        18: PPTX_IMG / "slide01.png",                   # Pytestwaf nine-phase / lifecycle overview
        19: PPTX_IMG / "slide02.png",                   # Component architecture
        20: DIAGRAMS / "waf-ml-bypass-by-encoder.png",        # Block/Bypass by encoder
        21: DIAGRAMS / "waf-ml-bypass-by-placement.png",      # Block/Bypass by placeholder
        22: DIAGRAMS / "waf-ml-encoder-placement-heatmap.png",# Encoder x Placement heat map
        23: DIAGRAMS / "waf-ml-attack-type-composition.png",  # Attack-type composition
        24: DIAGRAMS / "waf-ml-top-risk-ranked.png",          # Top risk ranked
        25: DIAGRAMS / "waf-mitre-attack.png",                # MITRE ATT&CK coverage
        26: DIAGRAMS / "waf-kill-chain.png",                  # Cyber kill-chain
        27: DIAGRAMS / "waf-tactic-radar.png",                # MITRE tactic radar
    }
    # Strict JCM mode: do not create extra figure* section breaks. The sample
    # document carries its own 14-section structure; adding a 1-col/2-col pair
    # around every wide chart expands the article to 50+ sections and no longer
    # follows the reference file.
    WIDE_FIGS: set[int] = set()
    # Single-column widths are used throughout so figures behave like the JCM
    # sample's in-flow figures and keep the template section structure intact.
    width_in = {
        1: 3.2,  2: 3.2,  3: 3.2,  4: 3.2,  5: 3.0,  6: 3.2,
        7: 3.2,  8: 3.2,  9: 3.2,  10: 3.2, 11: 3.2, 12: 3.2, 13: 3.2,
        14: 3.2, 15: 3.2, 16: 3.2, 17: 3.2, 18: 3.2, 19: 3.2,
        20: 3.2, 21: 3.2, 22: 3.2, 23: 3.2, 24: 3.2,
        25: 3.2, 26: 3.2, 27: 3.2,
    }

    cap_re = re.compile(r"^Fig\.\s+(\d+)\.\s")
    # Group candidate paragraphs per figure number. Prefer the article's own
    # body-positioned caption paragraphs over the original template caption
    # placeholders; otherwise figures get pulled into the old JCM positions
    # instead of the sections that discuss them.
    candidates: dict[int, list[Paragraph]] = {}
    for p in list(doc.paragraphs):
        m = cap_re.match(p.text.strip())
        if not m:
            continue
        n = int(m.group(1))
        candidates.setdefault(n, []).append(p)

    inserted = []
    for n in sorted(candidates):
        opts = candidates[n]
        body_positioned = [p for p in opts if p.style.name != "figure caption"]
        target = body_positioned[0] if body_positioned else opts[0]

        img = fig_map.get(n)
        if img is None or not img.exists():
            continue
        if target.style.name != "figure caption":
            target.style = doc.styles["figure caption"]
        insert_picture_before(
            target, img,
            width_in=width_in.get(n, 3.0),
            full_width=(n in WIDE_FIGS),
        )
        inserted.append(n)

        # Blank out duplicate paragraphs (kept the chosen target)
        for p in opts:
            if p is not target:
                replace_text(p, "")

    print(f"\nInserted {len(inserted)} figure images: {inserted}")
    _renumber_figure_references(doc)

    # ---------- final cleanup: remove orphan empty content placeholders ----
    # The dedup pass blanked out duplicate Fig caption paragraphs but left
    # them in the document as empty Body Text / figure caption paragraphs,
    # which render as visual blank lines. Drop them.
    removed = 0
    for p in list(doc.paragraphs):
        if p.style.name in {"Body Text", "figure caption"} and not p.text.strip():
            el = p._element
            # Skip if removing would orphan a section properties element
            if el.find(qn("w:pPr")) is not None and el.find(qn("w:pPr")).find(qn("w:sectPr")) is not None:
                continue
            el.getparent().remove(el)
            removed += 1
    print(f"Removed {removed} orphan empty content paragraphs")

    doc.save(str(OUTPUT))
    print(f"\nSaved {OUTPUT.name}")
    print(f"  paragraphs: {len(doc.paragraphs)}")
    print(f"  tables    : {len(doc.tables)}")


if __name__ == "__main__":
    edit_in_place()
