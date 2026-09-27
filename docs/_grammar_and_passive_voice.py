"""
Two-in-one fix:

  PART A — Replace the surviving " ,  " (comma + double-space) parenthetical
           placeholders with proper punctuation.  These were the original
           em-dash placeholders that the previous em-dash removal pass did
           not touch (because the pass only replaced U+2014, not the
           comma+spaces text).

  PART B — Convert clearly active-voice sentence openers ("This paper
           presents", "Fig. N illustrates", "Table N summarises", etc.) to
           passive voice ("X is presented in this paper", "X is illustrated
           in Fig. N", etc.).  Only patterns that have an unambiguous,
           grammatically clean passive transformation are touched.

Idempotent.  Backup created on first run.
"""
import re
import shutil
from pathlib import Path

from docx import Document

DOC = Path("pytestwaf-research-article.docx")
BAK = Path("pytestwaf-research-article.before-grammar-passive.docx")


def replace_paragraph_text(p, new_text: str) -> None:
    if not p.runs:
        p.add_run(new_text)
        return
    p.runs[0].text = new_text
    for r in p.runs[1:]:
        r.text = ""


# ---------------------------------------------------------------------------
# PART A — context-specific replacements for surviving " ,  " placeholders
# ---------------------------------------------------------------------------
A_FIXES = [
    # p131
    (
        "The four mutation mechanisms ,  pattern reuse, encoding chains, "
        "cross-category transfer, and structural mutation ,  are applied",
        "The four mutation mechanisms (pattern reuse, encoding chains, "
        "cross-category transfer, and structural mutation) are applied",
    ),
    # p161
    (
        "the random sampling performed by the mutation engine ,  for example, "
        "the choice of which encoder to chain on top of which successful "
        "template ,  is driven",
        "the random sampling performed by the mutation engine (for example, "
        "the choice of which encoder to chain on top of which successful "
        "template) is driven",
    ),
    # p210
    (
        "All numerical results in this section derive from the same scan-#22 "
        "evidence base ,  1,110 base payloads producing 403 blocks and 701 "
        "bypasses, plus 700 adaptive-round candidates ,  so that",
        "All numerical results in this section are derived from the same "
        "scan-#22 evidence base (1,110 base payloads producing 403 blocks "
        "and 701 bypasses, plus 700 adaptive-round candidates), so that",
    ),
    # p218
    (
        "The asymmetry between the two classes ,  bypassed F1 above blocked "
        "F1 ,  is operationally favourable",
        "The asymmetry between the two classes (bypassed F1 above blocked "
        "F1) is operationally favourable",
    ),
    # p221 — mean +/- std-dev notation
    (
        "Cross-validated F1 scores (mean ,  one standard deviation across the "
        "five folds) were:",
        "Cross-validated F1 scores (mean ± one standard deviation across the "
        "five folds) were:",
    ),
    # p224
    (
        "the linear baselines ,  Logistic Regression at 0.8971 and the RBF "
        "Support Vector Classifier at 0.9054 ,  and the K-Nearest "
        "Neighbours baseline",
        "the linear baselines (Logistic Regression at 0.8971 and the RBF "
        "Support Vector Classifier at 0.9054) and the K-Nearest Neighbours "
        "baseline",
    ),
    # p227
    (
        "additional base estimators with decorrelated error modes ,  for "
        "example, an Extremely Randomized Trees classifier or a small XGBoost "
        "model ,  might lift",
        "additional base estimators with decorrelated error modes (for "
        "example, an Extremely Randomized Trees classifier or a small "
        "XGBoost model) might lift",
    ),
    # p242 — explanatory clause: use colon
    (
        "indicating high bias and low variance ,  the linear decision boundary",
        "indicating high bias and low variance: the linear decision boundary",
    ),
    # p295
    (
        "A multi-target evaluation across diverse WAF deployments ,  managed "
        "rule groups, custom rule sets, mixed configurations, and "
        "detection-only configurations ,  would strengthen",
        "A multi-target evaluation across diverse WAF deployments (managed "
        "rule groups, custom rule sets, mixed configurations, and "
        "detection-only configurations) would strengthen",
    ),
    # p311
    (
        "the target's decision boundary is opaque, evolves over time, and "
        "admits black-box probing ,  for example, API-gateway authentication "
        "policies, content-delivery-network edge rules, and "
        "email-security-gateway anti-phishing rules.",
        "the target's decision boundary is opaque, evolves over time, and "
        "admits black-box probing (for example, API-gateway authentication "
        "policies, content-delivery-network edge rules, and "
        "email-security-gateway anti-phishing rules).",
    ),
]

# ---------------------------------------------------------------------------
# PART B — active-voice openers converted to passive voice
# ---------------------------------------------------------------------------
# Each entry is (regex_pattern, replacement_template).  The regex captures
# the object-of-verb fragment so we can re-thread it into the passive form.
#
# IMPORTANT: regex strings here use raw triple-quotes only where multi-line.

B_FIXES = [
    # ---- Paper / section / subsection openers -----------------------------
    (
        re.compile(r"This paper presents pytestwaf,"),
        "In this paper, pytestwaf is presented as",
    ),
    (
        re.compile(r"This section presents a complete overview of"),
        "A complete overview is presented in this section of",
    ),
    (
        re.compile(r"This section presents the methodology of"),
        "The methodology of",
    ),  # supplemented below to add "is presented in this section"
    (
        re.compile(r"This section reviews the weaknesses identified in"),
        "The weaknesses identified in",
    ),
    (
        re.compile(r"This section describes the experimental design used to"),
        "The experimental design used to",
    ),
    (
        re.compile(r"This subsection covers the final three phases of"),
        "The final three phases of",
    ),

    # ---- Fig. N XYZs --------------------------------------------------------
    (
        re.compile(r"Fig\. (\d+) illustrates "),
        r"Illustrated in Fig. \1 is ",
    ),
    (
        re.compile(r"Fig\. (\d+) depicts "),
        r"Depicted in Fig. \1 is ",
    ),
    (
        re.compile(r"Fig\. (\d+) presents "),
        r"Presented in Fig. \1 is ",
    ),
    (
        re.compile(r"Fig\. (\d+) shows "),
        r"Shown in Fig. \1 is ",
    ),
    (
        re.compile(r"Fig\. (\d+) provides "),
        r"Provided in Fig. \1 is ",
    ),
    (
        re.compile(r"Fig\. (\d+) visualises "),
        r"Visualised in Fig. \1 is ",
    ),
    (
        re.compile(r"Fig\. (\d+) ranks "),
        r"Ranked in Fig. \1 are ",
    ),
    (
        re.compile(r"Fig\. (\d+) reports "),
        r"Reported in Fig. \1 is ",
    ),
    (
        re.compile(r"Fig\. (\d+) compares "),
        r"Compared in Fig. \1 are ",
    ),
    (
        re.compile(r"Fig\. (\d+) decomposes "),
        r"Decomposed in Fig. \1 is ",
    ),
    (
        re.compile(r"Fig\. (\d+) complements Fig\. (\d+) with "),
        r"Fig. \1 is shown alongside Fig. \2, with ",
    ),

    # ---- Table N XYZs -------------------------------------------------------
    (
        re.compile(r"Table ([IVX]+) summarises "),
        r"Summarised in Table \1 are ",
    ),
    (
        re.compile(r"Table ([IVX]+) conducts a comparative analysis of"),
        r"A comparative analysis is conducted in Table \1 of",
    ),
    (
        re.compile(r"Table ([IVX]+) provides a comparative analysis of"),
        r"A comparative analysis is provided in Table \1 of",
    ),
    (
        re.compile(r"Table ([IVX]+) illustrates "),
        r"Illustrated in Table \1 is ",
    ),
]


def main():
    if not DOC.exists():
        raise SystemExit(f"Cannot find {DOC.resolve()}")
    if not BAK.exists():
        shutil.copyfile(DOC, BAK)
        print(f"Backup written: {BAK}")

    doc = Document(str(DOC))

    a_count = 0
    b_count = 0

    # PART A: text-substitution fixes
    for old, new in A_FIXES:
        for p in doc.paragraphs:
            if old in p.text:
                replace_paragraph_text(p, p.text.replace(old, new, 1))
                a_count += 1
                break
        else:
            print(f"  [skip A] anchor not found: {old[:80]!r}")

    # PART B: regex passive-voice rewrites
    for rx, repl in B_FIXES:
        for p in doc.paragraphs:
            if rx.search(p.text):
                new_text = rx.sub(repl, p.text, count=1)
                if new_text != p.text:
                    replace_paragraph_text(p, new_text)
                    b_count += 1
                    break

    # Special compound rewrites that need care:
    # "This section presents the methodology of the proposed hybrid
    #  machine-learning WAF validation framework. The methodology comprises
    #  ..." ->  "The methodology of the proposed hybrid machine-learning WAF
    #  validation framework is presented in this section. It comprises ..."
    for p in doc.paragraphs:
        s = p.text
        if s.startswith(
            "The methodology of the proposed hybrid machine-learning WAF "
            "validation framework. The methodology comprises four interlocking"
        ):
            new = s.replace(
                "The methodology of the proposed hybrid machine-learning WAF "
                "validation framework. The methodology comprises four "
                "interlocking",
                "The methodology of the proposed hybrid machine-learning WAF "
                "validation framework is presented in this section. It "
                "comprises four interlocking",
                1,
            )
            replace_paragraph_text(p, new)
            b_count += 1
            break

    # "The weaknesses identified in the current methods" -> add tail
    for p in doc.paragraphs:
        s = p.text
        if s.startswith(
            "The weaknesses identified in the current methods of WAF "
            "validation. The principal weaknesses are"
        ):
            new = s.replace(
                "The weaknesses identified in the current methods of WAF "
                "validation. The principal weaknesses are",
                "The weaknesses identified in the current methods of WAF "
                "validation are reviewed in this section. The principal "
                "weaknesses are",
                1,
            )
            replace_paragraph_text(p, new)
            b_count += 1
            break

    # "The experimental design used to validate the framework. The system
    #  architecture..."
    for p in doc.paragraphs:
        s = p.text
        if s.startswith(
            "The experimental design used to validate the framework. The "
            "system architecture"
        ):
            new = s.replace(
                "The experimental design used to validate the framework. "
                "The system architecture",
                "The experimental design used to validate the framework is "
                "described in this section. The system architecture",
                1,
            )
            replace_paragraph_text(p, new)
            b_count += 1
            break

    # "The final three phases of the methodology, namely Phase 7..."
    for p in doc.paragraphs:
        s = p.text
        if s.startswith(
            "The final three phases of the methodology, namely Phase 7"
        ):
            new = s.replace(
                "The final three phases of the methodology, namely Phase 7",
                "The final three phases of the methodology are covered in "
                "this subsection, namely Phase 7",
                1,
            )
            replace_paragraph_text(p, new)
            b_count += 1
            break

    # Final cleanup: tidy "is " followed by capitalised next word in inverted
    # passive constructions ("Illustrated in Fig. 5 is The...") — the captured
    # tail starts with "the four-layer", "the five-stage", etc. so no
    # capitalisation issue arises in practice.

    print(f"PART A (placeholder) edits applied: {a_count}/{len(A_FIXES)}")
    print(f"PART B (passive voice) edits applied: {b_count}")

    doc.save(str(DOC))
    print(f"Saved: {DOC}")


if __name__ == "__main__":
    main()
