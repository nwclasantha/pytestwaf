"""
Append 17 verified indexed peer-reviewed references ([34]-[50]) to the
references section of pytestwaf-research-article.docx, and inject inline
[N] citations into the most relevant body paragraphs.

All citations have been verified via web search (titles, authors, venues,
DOIs) before this script was generated. Run from the docs/ directory.
"""

from copy import deepcopy
import shutil
from pathlib import Path

from docx import Document

DOC = Path("pytestwaf-research-article.docx")
BAK = Path("pytestwaf-research-article.before-indexed-refs.docx")

# ---------------------------------------------------------------------------
# 1. Verified indexed references to append
# ---------------------------------------------------------------------------
NEW_REFS = [
    "[34] R. L. Alaoui and E. H. Nfaoui, “Deep Learning for Vulnerability and Attack Detection on Web Applications: A Systematic Literature Review,” Future Internet, vol. 14, no. 4, art. no. 118, 2022. doi: 10.3390/fi14040118.",
    "[35] B. R. Dawadi, B. Adhikari, and D. K. Srivastava, “Deep Learning Technique-Enabled Web Application Firewall for the Detection of Web Attacks,” Sensors, vol. 23, no. 4, art. no. 2073, 2023. doi: 10.3390/s23042073.",
    "[36] D. Appelt, C. D. Nguyen, A. Panichella, and L. C. Briand, “A Machine-Learning-Driven Evolutionary Approach for Testing Web Application Firewalls,” IEEE Transactions on Reliability, vol. 67, no. 3, pp. 733–757, Sep. 2018. doi: 10.1109/TR.2018.2805763.",
    "[37] M. Amouei, M. Rezvani, and M. Fateh, “RAT: Reinforcement-Learning-Driven and Adaptive Testing for Vulnerability Discovery in Web Application Firewalls,” IEEE Transactions on Dependable and Secure Computing, vol. 19, no. 5, pp. 3371–3386, Sep./Oct. 2022. doi: 10.1109/TDSC.2021.3095417.",
    "[38] L. Demetrio, A. Valenza, G. Costa, and G. Lagorio, “WAF-A-MoLE: Evading Web Application Firewalls through Adversarial Machine Learning,” in Proc. 35th Annual ACM Symposium on Applied Computing (SAC ’20), Brno, Czech Republic, 2020, pp. 1745–1752. doi: 10.1145/3341105.3373962.",
    "[39] S. Applebaum, T. Gaber, and A. Ahmed, “Signature-based and Machine-Learning-based Web Application Firewalls: A Short Survey,” Procedia Computer Science, vol. 189, pp. 359–367, 2021. doi: 10.1016/j.procs.2021.05.105.",
    "[40] A. Tekerek, “A novel architecture for web-based attack detection using convolutional neural network,” Computers & Security, vol. 100, art. no. 102096, 2021. doi: 10.1016/j.cose.2020.102096.",
    "[41] F. M. M. Mokbal, W. Dan, A. Imran, L. Jiuchuan, F. Akhtar, and W. Xiaoxi, “MLPXSS: An Integrated XSS-Based Attack Detection Scheme in Web Applications Using Multilayer Perceptron Technique,” IEEE Access, vol. 7, pp. 100567–100580, 2019. doi: 10.1109/ACCESS.2019.2927417.",
    "[42] R. Alhamyani and M. Alshammari, “Machine Learning-Driven Detection of Cross-Site Scripting Attacks,” Information, vol. 15, no. 7, art. no. 420, 2024. doi: 10.3390/info15070420.",
    "[43] M. Alghawazi, D. Alghazzawi, and S. Alarifi, “Deep Learning Architecture for Detecting SQL Injection Attacks Based on RNN Autoencoder Model,” Mathematics, vol. 11, no. 15, art. no. 3286, 2023. doi: 10.3390/math11153286.",
    "[44] M. Liu, K. Li, and T. Chen, “DeepSQLi: Deep Semantic Learning for Testing SQL Injection,” in Proc. 29th ACM SIGSOFT International Symposium on Software Testing and Analysis (ISSTA 2020), Virtual Event, USA, 2020, pp. 286–297. doi: 10.1145/3395363.3397375.",
    "[45] A. M. Vartouni, S. S. Kashi, and M. Teshnehlab, “An anomaly detection method to detect web attacks using Stacked Auto-Encoder,” in Proc. 6th Iranian Joint Congress on Fuzzy and Intelligent Systems (CFIS), Kerman, Iran, 2018, pp. 131–134. doi: 10.1109/CFIS.2018.8336654.",
    "[46] S. Toprak and A. G. Yavuz, “Web Application Firewall Based on Anomaly Detection using Deep Learning,” Acta Infologica, vol. 6, no. 2, pp. 219–244, 2022. doi: 10.26650/acin.1039042.",
    "[47] A. Rahman, C. Parnin, and L. Williams, “The Seven Sins: Security Smells in Infrastructure as Code Scripts,” in Proc. IEEE/ACM 41st International Conference on Software Engineering (ICSE 2019), Montreal, Canada, 2019, pp. 164–175. doi: 10.1109/ICSE.2019.00033.",
    "[48] B. Alouffi, M. Hasnain, A. Alharbi, W. Alosaimi, H. Alyami, and M. Ayaz, “A Systematic Literature Review on Cloud Computing Security: Threats and Mitigation Strategies,” IEEE Access, vol. 9, pp. 57792–57807, 2021. doi: 10.1109/ACCESS.2021.3073203.",
    "[49] C. Guo, G. Pleiss, Y. Sun, and K. Q. Weinberger, “On Calibration of Modern Neural Networks,” in Proc. 34th International Conference on Machine Learning (ICML 2017), Sydney, Australia, 2017, vol. 70, pp. 1321–1330.",
    "[50] A. Rahman, R. Mahdavi-Hezaveh, and L. Williams, “A systematic mapping study of infrastructure as code research,” Information and Software Technology, vol. 108, pp. 65–77, 2019. doi: 10.1016/j.infsof.2018.12.004.",
]


# ---------------------------------------------------------------------------
# 2. Inline citations to inject into body paragraphs
#    Each entry: (anchor_substring, replacement_substring)
#    Anchor must be unique across the whole document; we apply at most once
#    per paragraph and only if anchor is found.
# ---------------------------------------------------------------------------
INLINE_EDITS = [
    # Para 19 - existing tools and the gap they leave
    (
        "do not learn from prior scans against the same target, and do not emit executable remediation.",
        "do not learn from prior scans against the same target, and do not emit executable remediation [36], [37], [38], [44].",
    ),
    # Para 26 - vendor-managed rule groups motivation
    (
        "with respect to the attacker techniques catalogued in OWASP and in the MITRE ATT&CK",
        "with respect to the attacker techniques catalogued in OWASP and in the MITRE ATT&CK [34], [39]",
    ),
    # Para 32 - ML adoption in WAF testing
    (
        "Recent work extends ML to the WAF testing domain by training classifiers",
        "Recent work extends ML to the WAF testing domain [34], [35], [40], [45], [46] by training classifiers",
    ),
    # Para 33 - WAF design decisions / signature vs ML interaction
    (
        "WAFs expose two operating modes",
        "Comparative surveys of signature-based and ML-based WAFs [39] note that WAFs expose two operating modes",
    ),
    # Para 34 - stacking + calibration
    (
        "Stacking aggregates heterogeneous base estimators through a meta-learner",
        "Recent results on confidence calibration of modern neural networks [49] further motivate the post-hoc calibration step adopted here. Stacking aggregates heterogeneous base estimators through a meta-learner",
    ),
    # Para 35 - IaC emission (single ascending group at the tool-list anchor)
    (
        "Terraform, CloudFormation , Bicep, and gcloud each express a WAF rule as a declarative resource",
        "Terraform, CloudFormation , Bicep, and gcloud each express a WAF rule as a declarative resource [47], [48], [50],",
    ),
    # Para 39 - WAF validation research history
    (
        "later work introduced grammar-based generation, taint-tracking white-box methods",
        "later work introduced grammar-based generation, taint-tracking white-box methods [36], [37], [38], [44]",
    ),
    # Para 47 - case studies (ML-driven)
    (
        "ML-driven approaches consistently outperform fixed-corpus",
        "ML-driven approaches [35], [40], [41], [42], [43], [45], [46] consistently outperform fixed-corpus",
    ),
    # Para 49 - limitations
    (
        "(ii) absence of probability-calibrated bypass prediction",
        "(ii) absence of probability-calibrated bypass prediction [39], [49]",
    ),
    # Para 63 - methodology / FP rate
    (
        "do not respond fast enough to the elevated false-positive rate produced by static rule groups",
        "do not respond fast enough to the elevated false-positive rate produced by static rule groups [37], [40]",
    ),
]


# ---------------------------------------------------------------------------
# Repair edits — applied AFTER the inline edits above. These target the
# malformed prose and pre-existing out-of-order citations so that every
# paragraph's citations appear in strictly ascending order.
# ---------------------------------------------------------------------------
REPAIR_EDITS = [
    # p35: my prior insertion broke the "whose" relative clause. Collapse
    # the inserted sub-clause and restore the grammatical reference.
    (
        "[47], [50], and the broader cloud-security threat landscape that motivates such automated remediation has been systematically catalogued in [48] whose properties enumerate",
        "[47], [48], [50], whose properties enumerate",
    ),
    # p35: handle the version produced by the most recent INLINE_EDITS run
    # (single ascending group, with a trailing comma we now want to drop).
    (
        "[47], [48], [50],, and the broader cloud-security threat landscape that motivates such automated remediation has been systematically catalogued in [48] whose properties enumerate",
        "[47], [48], [50], whose properties enumerate",
    ),
    # p37: pre-existing IEEE order violation. Reorder the foundational-ML
    # topics so citations appear in ascending order, preserving meaning.
    (
        "including stacked generalisation [16], probability calibration [14], [15], statistical learning theory [12], and the deep-learning text by Goodfellow et al. [18]",
        "including statistical learning theory [12], probability calibration [14], [15], stacked generalisation [16], and the deep-learning text by Goodfellow et al. [18]",
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def replace_paragraph_text(paragraph, new_text):
    """Replace paragraph text while preserving the style of the first run.

    Body-Text paragraphs in this article are plain prose with no inline
    formatting, so collapsing to a single run is safe.
    """
    if not paragraph.runs:
        paragraph.add_run(new_text)
        return
    first = paragraph.runs[0]
    first.text = new_text
    for r in paragraph.runs[1:]:
        r.text = ""


def append_paragraph_after(paragraph, text, style):
    """Insert a new paragraph after `paragraph` carrying `text` in `style`."""
    new_p = deepcopy(paragraph._p)
    # clear all child elements (runs, properties); rebuild from scratch
    parent = paragraph._p.getparent()
    idx = list(parent).index(paragraph._p)
    # use add_paragraph on the document then move
    doc = paragraph.part.document
    fresh = doc.add_paragraph(text, style=style)
    parent.insert(idx + 1, fresh._p)
    return fresh


def main():
    if not DOC.exists():
        raise SystemExit(f"Cannot find {DOC.resolve()}")
    if not BAK.exists():
        shutil.copyfile(DOC, BAK)
        print(f"Backup written: {BAK}")
    else:
        print(f"Backup already exists: {BAK} (kept)")

    doc = Document(str(DOC))

    # ---- A. Inline citations -------------------------------------------------
    inline_applied = 0
    for anchor, repl in INLINE_EDITS:
        hit = False
        for p in doc.paragraphs:
            if anchor in p.text:
                replace_paragraph_text(p, p.text.replace(anchor, repl, 1))
                hit = True
                inline_applied += 1
                break
        if not hit:
            print(f"  [skip] anchor not found (already applied?): {anchor[:80]!r}")
    print(f"Inline citations applied this run: {inline_applied}/{len(INLINE_EDITS)}")

    # ---- A2. Repair edits (post-process) ------------------------------------
    repair_applied = 0
    for anchor, repl in REPAIR_EDITS:
        for p in doc.paragraphs:
            if anchor in p.text:
                replace_paragraph_text(p, p.text.replace(anchor, repl, 1))
                repair_applied += 1
                break
    print(f"Repair edits applied this run: {repair_applied}/{len(REPAIR_EDITS)}")

    # ---- B. Append references [34]-[50] -------------------------------------
    # Locate the last existing reference paragraph (style 'references')
    refs_paragraphs = [
        p for p in doc.paragraphs if p.style.name.lower() == "references"
    ]
    if not refs_paragraphs:
        raise SystemExit("Could not find any paragraph with style 'references'")
    last_ref = refs_paragraphs[-1]
    ref_style = last_ref.style.name

    # Idempotency: skip if the new refs are already appended
    existing_ref_text = "\n".join(p.text for p in refs_paragraphs)
    if "[50]" in existing_ref_text:
        print("References [34]-[50] already present — not re-appending.")
    else:
        cursor = last_ref
        for txt in NEW_REFS:
            cursor = append_paragraph_after(cursor, txt, ref_style)
        print(f"Appended references: {len(NEW_REFS)} (now [{34}]-[{33+len(NEW_REFS)}])")

    doc.save(str(DOC))
    print(f"Saved: {DOC}")


if __name__ == "__main__":
    main()
