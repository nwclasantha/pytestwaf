"""
Smooth out the stiff inverted-passive constructions left by the previous
"Illustrated in Fig. N is X" pass.

For each occurrence, transform:
    "[Verbed] in Fig. N (is|are) X[, optional tail]"
into:
    "X (is|are) [verbed] in Fig. N[, optional tail]"

This preserves the passive voice but reads as natural English.

Idempotent.  Backup on first run.
"""
from pathlib import Path
import shutil

from docx import Document

DOC = Path("pytestwaf-research-article.docx")
BAK = Path("pytestwaf-research-article.before-smooth-passive.docx")


def replace_text(p, new):
    if not p.runs:
        p.add_run(new)
        return
    p.runs[0].text = new
    for r in p.runs[1:]:
        r.text = ""


# Each entry: (anchor_substring, replacement_substring)
# Handcrafted for each paragraph since regex parsing of multi-clause
# noun-phrases is fragile.
EDITS = [
    # p21
    (
        "Provided in Fig. 1 is a 9-phase big-picture overview of the system "
        "showing how a single scan flows from CLI invocation through "
        "pre-flight, scanning, classification, learning, adaptive mutation, "
        "fix generation, reporting, and cross-scan memory.",
        "A 9-phase big-picture overview of the system, showing how a single "
        "scan flows from CLI invocation through pre-flight, scanning, "
        "classification, learning, adaptive mutation, fix generation, "
        "reporting, and cross-scan memory, is provided in Fig. 1.",
    ),
    # p39
    (
        "Summarised in Table I are the most cited academic and open-source "
        "contributions to WAF validation, indicating the tested WAF vendors, "
        "the testing methodology, and salient remarks on each contribution.",
        "The most cited academic and open-source contributions to WAF "
        "validation are summarised in Table I, indicating the tested WAF "
        "vendors, the testing methodology, and salient remarks on each "
        "contribution.",
    ),
    # p45
    (
        "Illustrated in Table I is the broad scope of academic work on WAF "
        "validation and demonstrates the prevalence of fixed-corpus, "
        "non-adaptive testing.",
        "The broad scope of academic work on WAF validation is illustrated "
        "in Table I, which demonstrates the prevalence of fixed-corpus, "
        "non-adaptive testing.",
    ),
    # p71
    (
        "Depicted in Fig. 2 is the proposed algorithm of the hybrid ML-based "
        "WAF validation framework. The algorithm presents an integrated "
        "processing of",
        "The proposed algorithm of the hybrid ML-based WAF validation "
        "framework is depicted in Fig. 2. An integrated processing of",
    ),
    # p101
    (
        "Illustrated in Fig. 5 is the four-layer response classification "
        "pipeline. Each HTTP response is processed",
        "The four-layer response classification pipeline is illustrated in "
        "Fig. 5. Each HTTP response is processed",
    ),
    # p147
    (
        "Presented in Fig. 8 is the experimental architecture, illustrating "
        "the deployment topology of the framework against a production target.",
        "The experimental architecture is presented in Fig. 8, illustrating "
        "the deployment topology of the framework against a production target.",
    ),
    # p250
    (
        "Decomposed in Fig. 20 is the block-versus-bypass distribution by "
        "encoder.",
        "The block-versus-bypass distribution by encoder is decomposed in "
        "Fig. 20.",
    ),
    # p253
    (
        "Reported in Fig. 21 is the same outcome decomposed by placeholder.",
        "The same outcome, decomposed by placeholder, is reported in Fig. 21.",
    ),
    # p256
    (
        "Visualised in Fig. 22 is the joint encoder x placeholder bypass-rate "
        "surface as a top-fifteen heat map.",
        "The joint encoder x placeholder bypass-rate surface is visualised "
        "in Fig. 22 as a top-fifteen heat map.",
    ),
    # p259
    (
        "Shown in Fig. 23 is the attack-type composition of the bypass "
        "candidates as a donut chart.",
        "The attack-type composition of the bypass candidates is shown in "
        "Fig. 23 as a donut chart.",
    ),
]


def main():
    if not DOC.exists():
        raise SystemExit(f"Cannot find {DOC.resolve()}")
    if not BAK.exists():
        shutil.copyfile(DOC, BAK)
        print(f"Backup written: {BAK}")

    doc = Document(str(DOC))
    applied = 0
    for old, new in EDITS:
        for p in doc.paragraphs:
            if old in p.text:
                replace_text(p, p.text.replace(old, new, 1))
                applied += 1
                break
        else:
            print(f"  [skip] anchor not found: {old[:80]!r}")
    print(f"Smoothed {applied}/{len(EDITS)} inverted-passive constructions")
    doc.save(str(DOC))
    print(f"Saved: {DOC}")


if __name__ == "__main__":
    main()
