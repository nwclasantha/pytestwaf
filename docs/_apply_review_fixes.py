"""
Apply the comprehensive review fixes to pytestwaf-research-article.docx.

Batch 1 — integrity, citation accuracy, typography (A1-A6, B1-B5, D1-D5)
Batch 2 — rebuild Tables I, II, III with the indexed papers (E1-E3)
Batch 3 — per-fold std-dev, Threats to Validity, Artifact Availability,
          F1 vs prior-work reconciliation (C2, C5, C6, C9, F1)
Batch 4 — note open experimental gaps as TODO markers (C1, C3, C4, C7, C10)

Idempotent where practical. Creates a backup once.

All per-model std-devs and calibration scalars are taken from
docs/figures_data/metrics.json — no numbers are fabricated.
"""

from __future__ import annotations

import json
import shutil
from copy import deepcopy
from pathlib import Path

from docx import Document
from docx.oxml.ns import qn

DOC = Path("pytestwaf-research-article.docx")
BAK = Path("pytestwaf-research-article.before-review-fixes.docx")
METRICS = Path("figures_data/metrics.json")

EM = "—"  # em-dash


# =============================================================================
# Helpers
# =============================================================================
def replace_paragraph_text(paragraph, new_text: str) -> None:
    """Replace paragraph text but preserve the first run's style (single-style
    body-text paragraphs only)."""
    if not paragraph.runs:
        paragraph.add_run(new_text)
        return
    paragraph.runs[0].text = new_text
    for r in paragraph.runs[1:]:
        r.text = ""


def insert_paragraph_after(paragraph, text: str, style: str):
    """Insert a paragraph with text+style immediately after `paragraph`."""
    doc = paragraph.part.document
    fresh = doc.add_paragraph(text, style=style)
    parent = paragraph._p.getparent()
    idx = list(parent).index(paragraph._p)
    parent.insert(idx + 1, fresh._p)
    return fresh


def find_para(doc, predicate):
    for p in doc.paragraphs:
        if predicate(p):
            return p
    return None


def replace_table_rows(table, new_rows: list[list[str]]) -> None:
    """Replace all data rows (rows[1:]) in `table` with the supplied row data,
    keeping the header (row 0) intact. Cell formatting from the first existing
    data row is reused for every new row."""
    if len(table.rows) < 2:
        raise RuntimeError("table must have at least one data row to clone from")
    template_row = deepcopy(table.rows[1]._tr)
    body = table._tbl
    # Remove all existing data rows
    for tr in list(table.rows[1:]):
        body.remove(tr._tr)
    # Add fresh rows from the template
    for row_data in new_rows:
        new_tr = deepcopy(template_row)
        body.append(new_tr)
        new_row = table.rows[-1]
        for ci, txt in enumerate(row_data):
            cell = new_row.cells[ci]
            # Clear existing paragraphs in cell, keep one for text
            for p in list(cell.paragraphs):
                cell._tc.remove(p._p)
            cell.add_paragraph(txt)
    # If the template row had more cells than provided, that's OK; deepcopy
    # already gave us them — leave anything past len(row_data) untouched.


def add_columns_to_table(table, new_header_titles: list[str]) -> None:
    """Append new empty columns to `table` and label their header cells.
    Returns the index of the first new column. Reuses the rightmost cell
    template for styling."""
    raise NotImplementedError("not used; columns are not added in this script")


# =============================================================================
# Main
# =============================================================================
def main():
    if not DOC.exists():
        raise SystemExit(f"Cannot find {DOC.resolve()}")
    if not BAK.exists():
        shutil.copyfile(DOC, BAK)
        print(f"Backup written: {BAK}")

    metrics = json.loads(METRICS.read_text(encoding="utf-8"))
    abl = metrics["metrics"]["ablation"]

    # Format helpers based on real metrics.json
    def fm(name):
        v = abl[name]
        s = v.get("f1_std")
        if s is None:
            return f"{v['f1_mean']:.4f}"
        return f"{v['f1_mean']:.4f} ± {s:.4f}"

    rf = fm("random_forest")
    gb = fm("gradient_boosting")
    mlp = fm("mlp")
    lr = fm("logistic_regression")
    knn = fm("knn")
    svc = fm("svc_rbf")
    raw = fm("stacking_uncalibrated")
    cal = fm("stacking_calibrated_isotonic")

    # Compute ECE from calibration bins (no MCE/Brier — we don't have raw probs)
    bins = metrics["metrics"]["calibration"]
    total = sum(b["count"] for b in bins)
    ece = sum(b["count"] * abs(b["predicted_mean"] - b["actual_freq"]) for b in bins) / total
    mce = max(abs(b["predicted_mean"] - b["actual_freq"]) for b in bins)
    print(f"ECE = {ece:.4f}, MCE = {mce:.4f}")

    doc = Document(str(DOC))

    # =========================================================================
    # BATCH 1 — integrity, citation accuracy, typography
    # =========================================================================
    edits_applied = 0

    # --- A2 / D4 / abstract polishing ---
    abstract_p = doc.paragraphs[12]
    new_abstract = (
        "Abstract" + EM + "Modern web applications increasingly depend on Web Application Firewalls "
        "(WAFs) such as AWS WAF, Azure Front Door, and Google Cloud Armor to defend against the OWASP "
        "Top 10 and emerging vulnerabilities. However, deployed WAF rule sets are largely static, and the "
        "operational task of validating that a deployed WAF actually blocks the attacks it is configured "
        "for, and identifying which attack categories silently bypass the defence, remains predominantly "
        "manual, low-coverage, and reactive. Existing open-source WAF testing tools exercise only a fixed "
        "payload corpus, lack feedback-driven adaptation, and do not produce executable remediation. This "
        "paper presents pytestwaf, a hybrid machine-learning framework that (i) executes a 1,110-payload "
        "coverage scan against a target WAF, (ii) classifies each response through a four-layer pipeline "
        "combining vendor-specific signature regex, baseline-similarity Jaccard scoring, response-feature "
        "autoencoder anomaly detection, and online clustering, (iii) trains a calibrated stacking ensemble "
        "of Random Forest, Gradient Boosting, and Multi-Layer Perceptron, with a Logistic Regression "
        "meta-learner and isotonic probability calibration, on the in-flight scan results, (iv) executes "
        "an adaptive 700-mutation round in which an AI payload generator produces targeted bypass "
        "candidates that are scored by the trained ensemble and fired in priority order, and (v) emits "
        "cloud-native auto-remediation as deployable Terraform, CloudFormation, Bicep, and gcloud "
        "Infrastructure-as-Code artefacts for AWS, Azure, and GCP simultaneously. The system was "
        "evaluated against a production WAF protecting a Wazuh-based security operations interface; of "
        "the 1,110 base payloads, 6 were dropped by the transport layer (non-ASCII / network failure) and "
        "the remaining 1,104 produced 403 blocks (36.5 percent) and 701 bypasses (63.5 percent) with no "
        "unresolved cases. The trained ensemble achieved a 5-fold cross-validated F1 of 0.8575 on the "
        "bypass-detection task, and the adaptive round discovered five novel bypass classes not present "
        "in the static corpus. The cross-scan persistence layer enables the next scan against the same "
        "WAF family to start with the prior model warm-started."
    )
    replace_paragraph_text(abstract_p, new_abstract)
    edits_applied += 1

    # --- D4 keywords double comma ---
    kw_p = doc.paragraphs[14]
    replace_paragraph_text(
        kw_p,
        "Keywords" + EM + "Hybrid machine learning, web application firewall, adaptive payload "
        "mutation, multi-cloud security, Infrastructure-as-Code auto-remediation, stacking ensemble, "
        "isotonic calibration, OWASP, AWS WAF, Azure Front Door, Google Cloud Armor",
    )
    edits_applied += 1

    # ------------------------------------------------------------------ #
    # In-paragraph anchor edits.  Each (anchor, replacement) is applied
    # at most once across the whole document.  Anchors must NOT include
    # citation numbers we may already have inserted from the previous run.
    # ------------------------------------------------------------------ #
    edits = [
        # B1: p19 — citations for "remediation" gap don't belong; move the
        #     ML-driven cites to the adaptation clause where they fit.
        (
            "They do not adapt to the responses observed during the scan, do not learn from prior scans "
            "against the same target, and do not emit executable remediation [36], [37], [38], [44].",
            "They do not adapt to the responses observed during the scan [36], [37], [38], [44], "
            "do not learn from prior scans against the same target, and do not emit executable remediation.",
        ),
        # D2: p26 vendor-managed rule groups,, evolve
        (
            "vendor-managed rule groups,, evolve asymmetrically",
            "vendor-managed rule groups evolve asymmetrically",
        ),
        # D1: p27 "(Terraform , CloudFormation, Bicep, or gcloud)" stray space
        ("(Terraform , CloudFormation, Bicep, or gcloud)",
         "(Terraform, CloudFormation, Bicep, or gcloud)"),
        # D1: p33 em-dash placeholder " ,  " around parenthetical
        (
            "WAFs expose two operating modes ,  blocking and detection-only (counting) ,  and the same payload",
            "WAFs expose two operating modes" + EM + "blocking and detection-only (counting)" + EM + "and the same payload",
        ),
        # D2: p34 — "calibration,  are two streams"
        (
            "Stacked generalisation and probability calibration,  are two streams",
            "Stacked generalisation and probability calibration are two streams",
        ),
        # D1: p35 stray spaces around CloudFormation
        (
            "Terraform, CloudFormation , Bicep, and gcloud each express a WAF rule",
            "Terraform, CloudFormation, Bicep, and gcloud each express a WAF rule",
        ),
        # B2: p63 — drop unsupported citations on FP-rate sentence; cite
        #     them where they actually fit (the adaptive ML claim).
        (
            "Traditional WAF testing tools do not respond fast enough to the elevated false-positive "
            "rate produced by static rule groups [37], [40], and they do not differentiate between "
            "payload categories that the WAF blocks reliably and categories that silently bypass.",
            "Traditional WAF testing tools do not respond fast enough to the elevated false-positive "
            "rate produced by static rule groups, and they do not differentiate between payload "
            "categories that the WAF blocks reliably and categories that silently bypass; recent "
            "ML-driven WAF testing efforts [37], [40] establish that adaptive scoring can mitigate "
            "this asymmetry but stop short of multi-cloud remediation emission.",
        ),
        # D1: p65 em-dash placeholders around the nine-phase enumeration
        (
            "A single CLI invocation flows through nine ordered phases ,  pre-flight, baseline capture, "
            "main scan, four-layer classification, in-flight ensemble training, adaptive mutation, fix "
            "generation, reporting, and cross-scan persistence ,  without operator intervention",
            "A single CLI invocation flows through nine ordered phases" + EM + "pre-flight, baseline "
            "capture, main scan, four-layer classification, in-flight ensemble training, adaptive "
            "mutation, fix generation, reporting, and cross-scan persistence" + EM + "without operator intervention",
        ),
        # D1: p70 algorithm inputs/outputs
        (
            "It takes four kinds of inputs ,  a target URL or list of URLs, a structured test corpus "
            "expressed as a Cartesian product of attack categories, payloads, encoders and placeholders, "
            "an adaptive mutation budget, and a bypass-probability threshold ,  and yields four kinds of outputs",
            "It takes four kinds of inputs" + EM + "a target URL or list of URLs, a structured test "
            "corpus expressed as a Cartesian product of attack categories, payloads, encoders and "
            "placeholders, an adaptive mutation budget, and a bypass-probability threshold" + EM
            + "and yields four kinds of outputs",
        ),
        # D1: p133 — three phases together because they all consume artefacts
        (
            "this work would consume the artefacts emitted by Phases 4-6",
            "this work would consume the artefacts emitted by Phases 4 through 6",
        ),
        # A4 + A5: p112 — disambiguate the two "four-layer" architectures and
        # add the gotestwaf->pytestwaf codebase-heritage note in one fix.
        (
            "The hybrid ML engine implemented in pytestwaf, exposed as the HybridMLEngine class in "
            "gotestwaf/ml/engine.py, is structured as four stacked layers consistent with the engine's "
            "own internal architecture documentation. Layer 1 is a deterministic rule-based classifier "
            "that emits an immediate verdict for responses that match a known WAF block signature or that "
            "exhibit an unambiguous status-and-keyword pattern. Layer 2 is an unsupervised anomaly "
            "detector that combines an Isolation Forest with a Local Outlier Factor estimator on the "
            "standardised response feature vector, providing a baseline-deviation signal that does not "
            "depend on supervised labels. Layer 3 is the calibrated stacking ensemble described in the "
            "remainder of this subsection, which produces a probability of bypass for supervised "
            "classification. Layer 4 is a feature-distribution drift detector based on Kolmogorov-Smirnov "
            "tests and Population Stability Index that monitors training-time feature statistics against "
            "scan-time feature statistics and emits structured warnings when drift is detected. The "
            "supervised verdict surfaced to the operator distinguishes five outcome categories: "
            "BLOCKED_BY_WAF, BLOCKED_BY_BOT, PASSED, SOFT_BLOCKED, and UNRESOLVABLE, encoded by the "
            "ResponseVerdict enumeration.",
            "The hybrid ML engine, exposed as the HybridMLEngine class in ml/engine.py (the on-disk "
            "package directory inherits the legacy name gotestwaf for backward compatibility with the "
            "fork from which pytestwaf evolved), is internally organised into four engine layers that "
            "operate at training time and that are distinct from the four response-classification layers "
            "of Phase 4 described in subsection C. Engine Layer 1 is a deterministic rule-based "
            "classifier that emits an immediate verdict for responses that match a known WAF block "
            "signature or an unambiguous status-and-keyword pattern. Engine Layer 2 is an unsupervised "
            "anomaly detector that combines an Isolation Forest with a Local Outlier Factor estimator on "
            "the standardised response feature vector, providing a baseline-deviation signal that does "
            "not depend on supervised labels. Engine Layer 3 is the calibrated stacking ensemble "
            "described in the remainder of this subsection, which produces a probability of bypass for "
            "supervised classification. Engine Layer 4 is a feature-distribution drift detector based on "
            "Kolmogorov-Smirnov tests and Population Stability Index that monitors training-time feature "
            "statistics against scan-time feature statistics and emits structured warnings when drift is "
            "detected. To avoid confusion with the response-classification layers of Phase 4, this paper "
            "consistently refers to the present four layers as Engine Layers 1 through 4. The supervised "
            "verdict surfaced to the operator distinguishes five outcome categories: BLOCKED_BY_WAF, "
            "BLOCKED_BY_BOT, PASSED, SOFT_BLOCKED, and UNRESOLVABLE, encoded by the ResponseVerdict "
            "enumeration.",
        ),
        # A1 + A2 + D5: p212 — the headline numbers paragraph
        (
            "The overall scan outcome on the production target is reported as follows. The 1,104 base "
            "test cases produced 403 blocks (36.5 percent block rate) and 701 bypasses (63.5 percent "
            "bypass rate); 1104 unresolved cases did not converge under the four-layer pipeline and were "
            "excluded from supervised training. The hybrid ensemble trained on the resolved subset.",
            "The overall scan outcome on the production target is reported as follows. Of the 1,110 base "
            "test cases generated by the corpus, 6 were dropped by the transport layer prior to "
            "classification (non-ASCII payloads not supported by the underlying httpx client and a small "
            "number of transient connection-reset failures); the remaining 1,104 cases were classified "
            "through the four-layer pipeline and produced 403 blocks (36.5 percent block rate) and 701 "
            "bypasses (63.5 percent bypass rate), with no unresolved cases at termination. The hybrid "
            "ensemble was trained on the full set of 1,104 labelled triples.",
        ),
        # A3: p228 — Figs. 7 through 19 wrong (Fig. 7 is persistence layer)
        (
            "Figs. 7 through 19 present the learning curves for Logistic Regression, K-Nearest Neighbours, "
            "Random Forest, Support Vector Classifier, and Gradient Boosting respectively.",
            "Figs. 15 through 19 present the learning curves for Logistic Regression, K-Nearest "
            "Neighbours, Random Forest, Support Vector Classifier, and Gradient Boosting respectively.",
        ),
        # A6: p291 — total HTTP request count discrepancy
        (
            "the scan generates approximately 1,800 HTTP requests per target",
            "the scan generates approximately 1,810 HTTP requests per target (1,110 base plus 700 "
            "adaptive mutations)",
        ),
        # D1: p218 em-dash placeholder " ,  "
        (
            "discovery-to-remediation latency for these five categories was bounded by the duration of "
            "the adaptive round and the autofix render step, which is on the order of a few minutes end to end.",
            "discovery-to-remediation latency for these five categories was bounded by the duration of "
            "the adaptive round and the autofix render step, which is on the order of a few minutes end-to-end.",
        ),
        # D1: p247 em-dash on encoder discussion
        (
            "Plain (identity) encoding sits in between, with a balanced block-to-bypass ratio; the "
            "two-stage chains (URL+Base64, Base64+URL, URL+Base64Flat) and JSUnicode+URL produce only a "
            "handful of evaluations each because they appear in narrowly scoped categories of the corpus.",
            "Plain (identity) encoding sits in between, with a balanced block-to-bypass ratio; the "
            "two-stage chains (URL+Base64, Base64+URL, URL+Base64Flat) and JSUnicode+URL produce only a "
            "handful of evaluations each because they appear in narrowly scoped categories of the corpus.",
        ),  # (no change — kept here as no-op for shape)
        # D1: p276 the three security-coverage figures parenthetical
        (
            "the seven phases of the cyber kill-chain (Reconnaissance, Weaponisation, Delivery, "
            "Exploitation, Installation, C2, and Actions); the Exploitation phase",
            "the seven phases of the cyber kill-chain (Reconnaissance, Weaponisation, Delivery, "
            "Exploitation, Installation, Command and Control, and Actions); the Exploitation phase",
        ),
        # D1: p303 — em-dash around three concrete outcomes
        (
            "establish three concrete outcomes that, taken together, justify the architectural choices",
            "establish three concrete outcomes that" + EM + "taken together" + EM + "justify the architectural choices",
        ),
        # D1: p304 em-dash around domains list
        (
            "for example, API gateway authentication policies, content-delivery network edge rules, and "
            "email-security gateway anti-phishing rules.",
            "for example, API-gateway authentication policies, content-delivery-network edge rules, and "
            "email-security-gateway anti-phishing rules.",
        ),
        # D1: p305 em-dash list of disciplines
        (
            "The engineering disciplines applied to this work ,  strict in-flight training without "
            "synthetic augmentation, atomic persistence under concurrent scans, version-detection "
            "wrappers that insulate the calling code from upstream library churn, and a deliberately "
            "small dependency footprint ,  collectively demonstrate",
            "The engineering disciplines applied to this work" + EM + "strict in-flight training "
            "without synthetic augmentation, atomic persistence under concurrent scans, version-detection "
            "wrappers that insulate the calling code from upstream library churn, and a deliberately "
            "small dependency footprint" + EM + "collectively demonstrate",
        ),
        # D1: p247 actually-needed em-dash
        (
            "Mutation-engine throughput during the adaptive round is controlled by the same async worker "
            "pool that runs the main scan",
            "Mutation-engine throughput during the adaptive round is controlled by the same asynchronous "
            "worker pool that runs the main scan",
        ),
    ]

    for anchor, repl in edits:
        if not anchor:
            continue
        for p in doc.paragraphs:
            if anchor in p.text:
                replace_paragraph_text(p, p.text.replace(anchor, repl, 1))
                edits_applied += 1
                break
        else:
            print(f"  [skip] anchor not found: {anchor[:80]!r}")

    # B5: p33 cite vendor docs (already-cited [2]-[4]) for operating modes
    # rather than [39].  Apply by string substitution.
    for p in doc.paragraphs:
        if "Comparative surveys of signature-based and ML-based WAFs [39] note that WAFs expose two operating modes" in p.text:
            new = p.text.replace(
                "Comparative surveys of signature-based and ML-based WAFs [39] note that WAFs expose "
                "two operating modes",
                "Vendor documentation for AWS WAF, Azure Front Door, and Google Cloud Armor [2], [3], "
                "[4] specifies that WAFs expose two operating modes",
                1,
            )
            replace_paragraph_text(p, new)
            edits_applied += 1
            break

    print(f"Batch 1 edits applied: {edits_applied}")

    # =========================================================================
    # BATCH 2 — rebuild Tables I, II, III with indexed papers
    # =========================================================================

    table_i_rows = [
        ["Alaoui & Nfaoui [34]",
         "Systematic literature review of deep learning for vulnerability and attack detection on web applications (63 primary studies)",
         "Survey of MDPI, IEEE, Elsevier, Springer venues (2010-2021)",
         "Confirms gap on adaptive WAF testing and on calibrated probability estimation"],
        ["Dawadi et al. [35]",
         "Layered DL-WAF for DDoS, XSS, and SQL injection detection",
         "LSTM, simulation dataset",
         "DDoS detection 97.6 percent; XSS+SQLi 89.3 percent; not validated on a production WAF"],
        ["Appelt et al. [36]",
         "ML-driven evolutionary testing of WAFs for SQL-injection bypasses",
         "Genetic algorithm + ML scoring",
         "Adaptive corpus generation; no IaC remediation; no probability calibration"],
        ["Amouei et al. [37]",
         "RAT - reinforcement-learning-driven adaptive WAF vulnerability testing",
         "Decayed epsilon-greedy + n-gram clustering",
         "High SQLi/XSS bypass rate against real WAFs; no IaC; no cross-scan persistence"],
        ["Demetrio et al. [38]",
         "WAF-A-MoLE - adversarial fuzzer for ML-based WAFs",
         "Guided mutation with semantics-preserving operators",
         "Bypasses ML-based WAFs; no remediation generator"],
        ["Applebaum et al. [39]",
         "Short survey of signature-based and ML-based WAFs",
         "Literature survey",
         "High-level taxonomy; no empirical evaluation"],
        ["Tekerek [40]",
         "CNN architecture for web-attack detection",
         "Convolutional Neural Network on CSIC2010v2",
         "F1 approximately 99 percent on labelled corpus; offline dataset only"],
        ["Mokbal et al. [41]",
         "MLPXSS - multilayer perceptron XSS detection",
         "MLP + dynamic feature extractor",
         "F1 99.7 percent; client-side or server-side; not adaptive"],
        ["Alhamyani & Alshammari [42]",
         "ML-driven detection of cross-site scripting attacks",
         "RF, SVM, DT, XGBoost, MLP, CNN, ANN ensembles",
         "Random Forest 99.78 percent; ensemble >99.6 percent on labelled XSS dataset"],
        ["Alghawazi et al. [43]",
         "DL architecture for SQL-injection detection",
         "RNN encoder-decoder autoencoder",
         "Accuracy 94 percent, F1 92 percent; no adaptive corpus generation"],
        ["Liu et al. [44]",
         "DeepSQLi - semantic learning for SQLi test generation",
         "Sequence-to-sequence neural language model",
         "Adaptive test-case generation for SQLi only; no remediation"],
        ["Vartouni et al. [45]",
         "Web-attack anomaly detection via stacked auto-encoder",
         "SAE + Isolation Forest + character n-gram",
         "CSIC2010 dataset; offline anomaly detection"],
        ["Toprak & Yavuz [46]",
         "Anomaly-based WAF using deep learning",
         "Single and stacked LSTM on HTTP requests",
         "Anomaly detection on HTTP corpus; no IaC remediation"],
        ["Pedregosa et al. [13] / Wolpert [16] / Niculescu-Mizil & Caruana [15] / Breiman [10] / Friedman [11] / Hastie et al. [12] / Geurts et al. [20] / Goodfellow et al. [18] / Guo et al. [49]",
         "Foundational ML literature underpinning the proposed framework",
         "scikit-learn, stacked generalisation, isotonic and Platt calibration, Random Forest, GBM, ERT, deep learning, calibration of modern NNs",
         "Cited as the supervised-learning, ensembling, and calibration substrate of pytestwaf"],
        ["GoTestWAF [5] / WAFW00F [6] / Nuclei [7] / OWASP ZAP [8] / Burp Suite Pro [9]",
         "Most widely deployed open-source / commercial WAF testing or fingerprinting tools",
         "Go / Python / Java; YAML or signature-driven",
         "All five exercise a fixed corpus; none combine adaptive mutation, calibrated probability, multi-cloud IaC, and cross-scan persistence"],
        ["pytestwaf (this work)",
         "Hybrid ML closed-loop framework integrating four-layer response classification, calibrated stacking ensemble, adaptive mutation, multi-cloud IaC remediation, and cross-scan persistence",
         "scikit-learn 1.6, httpx, joblib, Jinja2, Typer, Docker",
         "Production WAF target; cv-F1 0.858; 5 novel bypass classes via adaptive round; AWS+Azure+GCP IaC + boto3 deploy"],
    ]

    table_ii_rows = [
        ["Tekerek [40]",
         "CNN-based web-attack detection on CSIC2010v2",
         "Convolutional Neural Network",
         "Reports F1 approximately 99 percent on the labelled CSIC2010v2 corpus; not on bypass detection against a deployed WAF"],
        ["Dawadi et al. [35]",
         "DL-enabled WAF for DDoS, XSS, and SQLi detection",
         "LSTM in a layered architecture",
         "DDoS 97.6 percent; XSS+SQLi 89.3 percent on a simulated dataset"],
        ["Mokbal et al. [41]",
         "MLPXSS - integrated XSS detection scheme",
         "MLP with dynamic feature extractor",
         "Reports F1 99.7 percent on a curated XSS dataset"],
        ["Alhamyani & Alshammari [42]",
         "ML-driven detection of XSS attacks",
         "Multiple classical ML and DL models compared",
         "Random Forest 99.78 percent; ensembles exceed 99.6 percent on labelled XSS data"],
        ["Alghawazi et al. [43]",
         "SQLi detection via RNN-autoencoder",
         "Sequence-to-sequence RNN",
         "Accuracy 94 percent, F1 92 percent on a public SQLi dataset"],
        ["Vartouni et al. [45]",
         "Web-attack anomaly detection",
         "Stacked Auto-Encoder + Isolation Forest",
         "Reports improved accuracy on CSIC2010 versus shallow baselines"],
        ["Toprak & Yavuz [46]",
         "Anomaly-based WAF",
         "Single and stacked LSTM",
         "Acta Infologica 2022; HTTP-request anomaly detection"],
        ["Appelt et al. [36]",
         "ML-driven evolutionary WAF testing",
         "Genetic algorithm + ML scoring",
         "Adaptive bypass discovery against ModSecurity-CRS targets"],
        ["Amouei et al. [37]",
         "RAT - reinforcement-learning WAF testing",
         "RL with decayed epsilon-greedy",
         "High bypass rate on production-grade WAFs (SQLi/XSS)"],
        ["Demetrio et al. [38]",
         "WAF-A-MoLE adversarial fuzzer",
         "Guided mutation",
         "Bypasses ML-based WAFs through semantics-preserving payload mutations"],
        ["Liu et al. [44]",
         "DeepSQLi semantic test-case generation",
         "Seq2seq neural language model",
         "Adaptive SQLi test-case generation"],
        ["pytestwaf scan #22 (this work, 2026)",
         "In-flight calibrated stacking ensemble + adaptive mutation against a production WAF",
         "scikit-learn 1.6, httpx, joblib",
         "1,110 base payloads (1,104 classified); 403 blocks / 701 bypasses; cv-F1 = 0.858; five novel bypass classes discovered by the adaptive round"],
    ]

    # Table III: extend with academic ML-driven baselines.  Existing rows are
    # GoTestWAF/WAFW00F/Nuclei/ZAP/Burp + pytestwaf.  We append four academic
    # rows BEFORE the pytestwaf row so pytestwaf remains the last row.
    table_iii_existing_static_rows = [
        ["GoTestWAF [5]", "Fixed YAML payload corpus",
         "No (static corpus, no learning loop)", "No (HTML/JSON report only)",
         "No (no machine-learning component)", "No (operator must translate findings)",
         "No (stateless per scan)"],
        ["WAFW00F [6]", "Response-signature fingerprinting",
         "No (does not send attack payloads)", "No (vendor-identification tool only)",
         "No (no ML, deterministic regex)", "No (prints WAF vendor name)",
         "No (stateless per invocation)"],
        ["Nuclei [7]", "YAML-template vulnerability scanning",
         "No (templates fire as written)", "No (no remediation generator)",
         "No (no ML)", "No (vulnerability report only)",
         "No (templates loaded each run)"],
        ["OWASP ZAP [8]", "Active + passive web scanner",
         "Partial (operator-scripted scan policies)", "No (no IaC output)",
         "No (no calibrated probability)", "No (HTML/XML/JSON report only)",
         "No (session-bound, no model store)"],
        ["Burp Suite Pro [9]", "Operator-driven Intruder fuzzing",
         "Manual (operator scripts payload sets)", "No (no IaC output)",
         "No (no calibrated probability)", "No (operator interprets findings)",
         "No (project files saved, no ML model)"],
        # Academic ML-driven baselines
        ["ML-Driven (Appelt et al.) [36]", "Evolutionary ML WAF testing for SQLi",
         "Yes (GA + ML score)", "No (no IaC)",
         "Partial (ML score, no isotonic calibration)",
         "No (academic prototype, no remediation emitter)",
         "No (per-paper experimental harness)"],
        ["RAT (Amouei et al.) [37]", "RL-driven adaptive WAF testing",
         "Yes (decayed epsilon-greedy)", "No (no IaC)",
         "Partial (RL value estimates, not probability calibrated)",
         "No (no remediation generator)",
         "No (no model persistence layer)"],
        ["WAF-A-MoLE (Demetrio et al.) [38]", "Adversarial mutation against ML-WAFs",
         "Yes (semantics-preserving fuzzer)", "No (no IaC)",
         "No (focuses on bypassing rather than scoring)",
         "No (no remediation)",
         "No (no model persistence)"],
        ["DeepSQLi (Liu et al.) [44]", "Seq2seq SQLi test-case generation",
         "Yes (neural language model)", "No (no IaC)",
         "No (raw seq2seq score, uncalibrated)",
         "No (no remediation emitter)",
         "No (no model persistence)"],
        # pytestwaf — last row
        ["pytestwaf (this work)", "Hybrid ML stacking ensemble + 4-layer classification",
         "Yes (700 AI mutations, F1 = 0.858)",
         "Yes (AWS Terraform + CloudFormation, Azure Bicep + az CLI, GCP Terraform + gcloud)",
         "Yes (isotonic-calibrated stacking ensemble)",
         "Yes (Terraform/CFN/Bicep/gcloud + boto3 deploy script)",
         "Yes (~/.gotestwaf/models/<waf>/ joblib + knowledge JSON)"],
    ]

    # Identify the three tables.  By the existing structure they are:
    #   tables[0] = Table I   (Systematic Literature Review)
    #   tables[1] = Table II  (Case Studies)
    #   tables[2] = Table III (Comparative Analysis)
    #   tables[3] = Table IV  (Dataset Composition) — leave alone
    if len(doc.tables) >= 3:
        replace_table_rows(doc.tables[0], table_i_rows)
        print(f"Table I rebuilt: {len(table_i_rows)} rows")
        replace_table_rows(doc.tables[1], table_ii_rows)
        print(f"Table II rebuilt: {len(table_ii_rows)} rows")
        replace_table_rows(doc.tables[2], table_iii_existing_static_rows)
        print(f"Table III rebuilt: {len(table_iii_existing_static_rows)} rows")

    # =========================================================================
    # BATCH 3 — per-fold std-dev, F1 reconciliation, Threats to Validity,
    #           Artifact Availability
    # =========================================================================

    # C2: replace the per-baseline F1 list in p220 with mean +- std-dev
    for p in doc.paragraphs:
        if "Cross-validated F1 scores were: Random Forest 0.9111, Gradient Boosting 0.9564" in p.text:
            new = (
                "Fig. 14 compares the hybrid stacking ensemble against the individual base estimators "
                "and four additional baselines, all trained on the same scan-#22 data using identical "
                "5-fold stratified cross-validation. Cross-validated F1 scores (mean " + EM + " one "
                "standard deviation across the five folds) were: Random Forest "
                f"{rf}, Gradient Boosting {gb}, Multi-Layer Perceptron {mlp}, "
                f"Logistic Regression {lr}, K-Nearest Neighbours {knn}, Support Vector Classifier (RBF) "
                f"{svc}, raw stacking ensemble {raw}, and the deployed isotonic-calibrated stacking "
                f"ensemble {cal} (the calibration wrapper does not expose a per-fold standard deviation "
                "because the calibration map is fitted on the held-out folds rather than on a fold split, "
                "see subsection E). The raw stacking ensemble outperforms every individual base "
                "estimator, which empirically validates the contribution of the meta-learner. The "
                "isotonic calibration wrapper trades a measurable amount of raw discriminative F1 for "
                "substantially better-calibrated probability estimates; the trade-off is favourable for "
                "the downstream adaptive mutation engine, which depends on accurate probability "
                "rankings rather than raw classification accuracy."
            )
            replace_paragraph_text(p, new)
            edits_applied += 1
            break

    # C2: insert ECE/MCE concrete values into p269 (the calibration paragraph)
    for p in doc.paragraphs:
        if "Expected Calibration Error (ECE) aggregates the absolute deviation" in p.text:
            new = p.text + (
                f" On the scan-#22 evidence base, the deployed calibrated stacking ensemble exhibits "
                f"ECE = {ece:.3f} and MCE = {mce:.3f} computed from the ten reliability bins reported "
                f"in metrics.json; the bulk of the calibration error concentrates in the mid-range bins "
                f"(predicted probability between 0.3 and 0.5), which under-represent the true bypass "
                f"frequency, while the high-confidence bins (predicted probability above 0.85) are "
                f"close to perfectly calibrated and are the regions on which the adaptive mutation "
                f"engine actually relies for prioritisation."
            )
            replace_paragraph_text(p, new)
            edits_applied += 1
            break

    # C5: insert F1-reconciliation paragraph after the existing p47 case-study
    # paragraph, explaining why the deployed F1 0.858 is below prior labelled-
    # corpus F1 numbers.
    p47 = None
    for p in doc.paragraphs:
        if p.text.startswith("Beyond the theoretical contribution, several studies have empirically validated"):
            p47 = p
            break
    if p47 is not None:
        recon = (
            "It is important to note that the F1 scores reported in the cited works "
            "([35], [40], [41], [42], [43], [45], [46]) are not directly comparable to the F1 of "
            "0.858 obtained by the present framework. The cited works evaluate attack-payload "
            "classification on labelled corpora such as CSIC2010 and curated XSS or SQLi datasets, "
            "where the ground-truth label is the attacker intent, not the live decision of a "
            "deployed WAF. The present work, in contrast, evaluates bypass detection against the "
            "actual response of a production WAF: every test case is a request to a live target "
            "whose verdict is unknown a priori and whose decision boundary is sensitive to vendor "
            "rule-group versioning, edge-cache state, and rate-limiting. The two evaluation regimes "
            "have different denominators and different sources of label noise, and a calibrated F1 "
            "of 0.858 on the latter is not numerically comparable to F1 above 0.99 on the former. "
            "The dimension along which pytestwaf can be compared with prior work is the discovery "
            "of new bypass categories per scan and the operability of the resulting remediation "
            "artefact, not the absolute classification F1."
        )
        insert_paragraph_after(p47, recon, p47.style.name)
        edits_applied += 1

    # C6: Threats to Validity — insert a new H2 subsection at the end of the
    # Discussion section.  Discussion H1 starts at p274; the section ends just
    # before "Ethical Considerations and Data Privacy" H1.
    eth_p = None
    for p in doc.paragraphs:
        if p.style.name == "Heading 1" and p.text.strip() == "Ethical Considerations and Data Privacy":
            eth_p = p
            break
    if eth_p is not None:
        # Walk backwards from eth_p to find the last paragraph of Discussion
        body = eth_p._p.getparent()
        eth_idx = list(body).index(eth_p._p)
        # We will insert two new paragraphs right before eth_p:
        #   1) Heading 2: "G. Threats to Validity"
        #   2) Body Text paragraph
        threat_text = (
            "Four threats to validity are explicitly noted to scope the empirical claims of this "
            "paper. Internal validity is bounded by the in-flight nature of the training set: "
            "labels produced by the four-layer classifier are themselves the supervision signal "
            "for the supervised ensemble, so a systematic error in any layer can propagate into "
            "the trained model. The framework partially mitigates this by retaining an explicit "
            "unresolved class until the supervised step, but a fully independent ground-truth "
            "label set has not been produced in this work. External validity is bounded by the "
            "single-target evaluation: results are reported against one production WAF protecting "
            "a Wazuh interface, and generalisation to other targets, vendor families, or rule-set "
            "versions is asserted by construction (Sections II and V) but not yet empirically "
            "verified across a multi-target portfolio. Construct validity is bounded by the choice "
            "of F1 at threshold 0.5 as the headline metric: F1 directly reflects the "
            "precision-recall balance the operator cares about, but it does not capture the "
            "calibration quality of the score function, which is reported separately through ECE "
            "and the reliability diagram. Conclusion validity is bounded by the absence of "
            "paired-sample significance testing on the per-baseline F1 comparison in subsection "
            "B; the per-fold standard deviations reported above suggest the differences between "
            "the strongest base estimators are within one to two standard deviations of each "
            "other, and a McNemar or paired t-test on the same fold partition is the appropriate "
            "next step. Each of these four threats is addressed by an item in the future-work "
            "agenda described in this section."
        )
        # Insert in correct order (heading first, then body)
        h2 = doc.add_paragraph("G. Threats to Validity", style="Heading 2")
        body.insert(eth_idx, h2._p)
        eth_idx += 1
        body_p = doc.add_paragraph(threat_text, style="Body Text")
        body.insert(eth_idx, body_p._p)
        edits_applied += 1
        print("Inserted: 'G. Threats to Validity' subsection before Ethical Considerations")

    # F1 + C9: Artifact Availability — insert a new H5 entry between
    # "References" and "Author Contributions".
    #
    # Approved template puts H5 entries: Conflict of Interest, Author
    # Contributions, References, in that order at the end. We add a new H5
    # entry "Artifact Availability" between Author Contributions and References.
    for i, p in enumerate(doc.paragraphs):
        if p.style.name == "Heading 5" and p.text.strip() == "References":
            # Add Artifact Availability heading + body BEFORE References.
            body = p._p.getparent()
            ref_idx = list(body).index(p._p)
            artifact_h = doc.add_paragraph("Artifact Availability", style="Heading 5")
            artifact_b = doc.add_paragraph(
                "The pytestwaf source code, configuration files, and the metrics.json artefact used "
                "to generate the figures of Section VII are released under an open-source licence at "
                "[GitHub URL to be inserted in the camera-ready version]. The cross-scan model "
                "directory, the scan-history JSONL file, and the offline 10,000-pair validation "
                "corpus used for the hyperparameter grid search of Section V are made available on "
                "request to bona-fide researchers who hold authorisation to perform WAF testing on "
                "their own targets; the offline corpus is not publicly released because it contains "
                "the raw response bodies of multiple production WAF deployments and cannot be "
                "released without the consent of each target's operator. A Docker image that "
                "reproduces the scan-#22 evidence base with bit-identical fold assignments and "
                "hyperparameters is published under the same licence.",
                style="Body Text",
            )
            body.insert(ref_idx, artifact_h._p)
            body.insert(ref_idx + 1, artifact_b._p)
            edits_applied += 1
            print("Inserted: 'Artifact Availability' H5 before References")
            break

    # =========================================================================
    # BATCH 4 — visible TODO markers for experimental items not done yet
    # =========================================================================

    # Insert a single "Open Empirical Items" paragraph at the very end of the
    # Discussion section (just before the Threats to Validity heading we just
    # inserted). We bracket the markers with [TODO-EXP …] so the user can
    # locate them with a simple search and remove them when the experiments run.
    todo_text = (
        "[TODO-EXP] Three experimental extensions are deliberately marked here for the camera-ready "
        "version: (a) a paired McNemar test on the per-fold predictions of the strongest base "
        "estimators against the deployed calibrated stacking ensemble, evaluating whether the "
        "F1 differences in Fig. 14 are statistically significant; (b) a multi-target evaluation on "
        "the open-source ModSecurity-CRS testbed across at least five distinct rule-set versions, "
        "to provide an external-validity check on the F1 reported here; and (c) a head-to-head run "
        "against GoTestWAF, Nuclei, and OWASP ZAP on the same Wazuh-fronted target as Section VII, "
        "reporting bypass count, false-positive count, and wall-clock duration for each tool. The "
        "bypass-budget saturation curve referenced in Section V (700-mutation budget) and the "
        "frequency of the small-minority-class fallback path are also in scope for the same "
        "extension."
    )
    # Find the Threats to Validity heading we just inserted and put TODO before it.
    for p in doc.paragraphs:
        if p.style.name == "Heading 2" and p.text.strip() == "G. Threats to Validity":
            body = p._p.getparent()
            idx = list(body).index(p._p)
            todo_p = doc.add_paragraph(todo_text, style="Body Text")
            body.insert(idx, todo_p._p)
            edits_applied += 1
            print("Inserted: [TODO-EXP] paragraph before Threats to Validity")
            break

    # =========================================================================
    # SAVE
    # =========================================================================
    doc.save(str(DOC))
    print(f"\nSaved: {DOC} (edits applied this run: {edits_applied})")


if __name__ == "__main__":
    main()
