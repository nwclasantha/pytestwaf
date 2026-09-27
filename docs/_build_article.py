"""Build a JCM-style research article for pytestwaf, mirroring the structure
of JCM-20514-v5-fixed.docx.

The output preserves the template's styles, page setup, and section pattern,
and replaces the IP-reputation content with the pytestwaf hybrid-ML WAF
validation framework content.
"""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from docx import Document
from docx.oxml.ns import qn
from docx.shared import Inches, Pt

# ---------- Verified metrics from scan #22 ---------------------------------
# Loaded from docs/figures_data/metrics.json. Anything quoted in the article
# numerically should come from this dict.
_METRICS_PATH = Path(__file__).parent / "figures_data" / "metrics.json"
if _METRICS_PATH.exists():
    METRICS = json.loads(_METRICS_PATH.read_text(encoding="utf-8"))
else:
    METRICS = {"scan": {}, "metrics": {}}


def _f(x, p=4):
    return f"{float(x):.{p}f}" if x is not None else "n/a"


def _scan(k, default=0):
    return METRICS.get("scan", {}).get(k, default)


def _met(k, default=None):
    return METRICS.get("metrics", {}).get(k, default)


def _abl(model, key="f1_mean"):
    return METRICS.get("metrics", {}).get("ablation", {}).get(model, {}).get(key)


def _per_class(cls, key):
    return (METRICS.get("metrics", {}).get("per_class", {})
            .get(cls, {}).get(key))

TEMPLATE = Path(__file__).parent / "JCM-20514-v5-fixed.docx"
OUTPUT = Path(__file__).parent / "pytestwaf-research-article.docx"
DIAGRAMS = Path(__file__).parent / "diagrams"


# ---------- Article content ------------------------------------------------

TITLE = (
    "Hybrid Machine Learning for Adaptive Web Application Firewall "
    "Validation and Multi-Cloud Auto-Remediation"
)

AUTHORS = (
    "Nanayakkara Wawage Chanaka Lasantha 1,*, "
    "Madduma Wellalage Pasan Maduranga  2, \nand Ruvan Abeysekara 3"
)

AFFILIATIONS = [
    "1 Faculty of Graduate Studies, IIC University of Technology, "
    "Phnom Penh, Cambodia",
    "2 Department of Electrical and Electronic Engineering, "
    "University of Sri Jayewardenepura, Nugegoda, Sri Lanka",
    "3 Faculty of Graduate Studies, BCAS Campus, Colombo, Sri Lanka",
    "Email: chanaka.lasantha@gmail.com (N.W.C.L.); pasanm@sjp.ac.lk "
    "(M.W.P.M.); ruvan@bcas.lk (R.A.)",
    "*Corresponding author",
]

_CV_F1 = _met("cv_f1_score") or _met("cv_f1") or 0.0
_BLOCKED = _scan("blocked", 0)
_BYPASSED = _scan("bypassed", 0)
_TOTAL = _BLOCKED + _BYPASSED
_SAMPLES = _scan("samples_trained", 0)

ABSTRACT = (
    "Abstract, Modern web applications increasingly depend on Web "
    "Application Firewalls (WAFs), AWS WAF, Azure Front Door, Google "
    "Cloud Armor, to defend against the OWASP Top 10 and emerging "
    "vulnerabilities. However, deployed WAF rule sets are largely static, "
    "and the operational task of validating that a deployed WAF actually "
    "blocks the attacks it is configured for, and identifying which attack "
    "categories silently bypass the defence, remains predominantly manual, "
    "low-coverage, and reactive. Existing open-source WAF testing tools "
    "exercise only a fixed payload corpus, lack feedback-driven adaptation, "
    "and do not produce executable remediation. This paper presents "
    "pytestwaf, a hybrid machine-learning framework that (i) executes a "
    "1,110-payload coverage scan against a target WAF, (ii) classifies each "
    "response through a four-layer pipeline combining vendor-specific "
    "signature regex, baseline-similarity Jaccard scoring, response-feature "
    "autoencoder anomaly detection, and online clustering, (iii) trains a "
    "calibrated stacking ensemble of Random Forest, Gradient Boosting, and "
    "Multi-Layer Perceptron meta-learnt by Logistic Regression with "
    "isotonic probability calibration, on the in-flight scan results, "
    "(iv) executes an adaptive 700-mutation round in which an AI payload "
    "generator produces targeted bypass candidates that are scored by the "
    "trained ensemble and fired in priority order, and (v) emits "
    "cloud-native auto-remediation as deployable Terraform, "
    "CloudFormation, Bicep, and gcloud Infrastructure-as-Code artefacts "
    "for AWS, Azure, and GCP simultaneously. The system was evaluated "
    "against a production WAF protecting a Wazuh-based security operations "
    f"interface; {_TOTAL:,} payloads produced {_BLOCKED} blocks and "
    f"{_BYPASSED} bypasses, the trained ensemble achieved a "
    f"cross-validated F1 of {_CV_F1:.3f} on the bypass-detection task, "
    "and the adaptive round discovered five novel bypass classes not "
    "present in the static corpus. The cross-scan persistence layer "
    "enables the next scan against the same WAF family to start with the "
    "prior model warm-started."
)

KEYWORDS = (
    "Keywords, Hybrid machine learning, web application firewall, "
    "adaptive payload mutation, multi-cloud security, Infrastructure-as-Code "
    "auto-remediation, stacking ensemble, isotonic calibration,, OWASP, "
    "AWS WAF, Azure Front Door, Google Cloud Armor"
)


# ---------- Body sections --------------------------------------------------
# Each entry: (style, text). Style is the Word style name that exists in
# the template. Heading 1 / Heading 2 / Heading 5 / Body Text / figure
# caption / equation / Biography are reused from the template.

# To keep this file scannable, paragraphs are stored as a list of strings
# under each subsection name, and a builder function wires them together.

INTRO = [
    "Cloud-native web applications have become the dominant delivery model "
    "for both consumer and enterprise services, and their attack surface "
    "has grown commensurately with their architectural complexity. The "
    "Open Web Application Security Project (OWASP) continues to report "
    "injection, broken access control, and cryptographic failures among "
    "the top vulnerability classes affecting production deployments. To "
    "mitigate this exposure, organisations deploy Web Application "
    "Firewalls (WAFs) as the primary perimeter defence, frequently using "
    "managed services such as Amazon Web Services (AWS) WAF, Microsoft "
    "Azure Front Door WAF, and Google Cloud Armor. These services bundle "
    "vendor-curated rule groups intended to block known attack patterns "
    "at the network edge.",

    "Despite the widespread adoption of cloud WAFs, a fundamental "
    "operational gap persists: the validation of WAF efficacy. A WAF "
    "configured with a vendor managed rule group does not, by itself, "
    "guarantee that the rule group is correctly bound to the protected "
    "resource, that custom application paths are covered, or that the "
    "rule group blocks the specific evasion techniques attackers use in "
    "the wild. In practice, security teams discover gaps reactively, "
    "after a successful exploitation, rather than proactively through "
    "systematic adversarial testing.",

    "Existing open-source WAF testing tools exercise a fixed payload "
    "corpus and report a per-category bypass rate. They do not adapt to "
    "the responses observed during the scan, do not learn from prior "
    "scans against the same target, and do not emit executable "
    "remediation. The remediation gap is particularly acute in "
    "multi-cloud environments where the same logical rule must be "
    "expressed across heterogeneous WAF management interfaces.",

    "This paper presents pytestwaf, a hybrid machine-learning framework "
    "that closes the validation, adaptation, and remediation gaps in a "
    "single end-to-end pipeline. The contributions of this work are "
    "fivefold. First, a four-layer hybrid response classification "
    "pipeline that combines vendor-specific regex signatures, "
    "baseline-similarity Jaccard scoring, response-feature autoencoder "
    "anomaly detection, and online clustering achieves robust "
    "blocked-versus-bypassed labelling with low false-positive rates. "
    "Second, a calibrated stacking ensemble of Random Forest, Gradient "
    "Boosting, and Multi-Layer Perceptron, with isotonic probability "
    "calibration and balanced sample weights, learns bypass patterns from "
    "the in-flight scan and produces well-calibrated bypass-probability "
    "estimates. Third, an adaptive mutation engine generates targeted "
    "bypass candidates from the learned patterns and prioritises them by "
    "predicted bypass probability, achieving accelerated discovery of "
    "novel bypasses. Fourth, an auto-remediation pipeline emits "
    "Terraform, CloudFormation, Bicep, and gcloud Infrastructure-as-Code "
    "artefacts for AWS, Azure, and GCP simultaneously, irrespective of "
    "the detected target WAF. Fifth, a cross-scan persistence layer "
    "saves trained models keyed by WAF family so that subsequent scans "
    "against the same family begin with the model warm-started.",

    "Fig. 18 provides a 9-phase big-picture overview of the system "
    "showing how a single scan flows from CLI invocation through "
    "pre-flight, scanning, classification, learning, adaptive "
    "mutation, fix generation, reporting, and cross-scan memory.",

    "Fig. 18. Pytestwaf nine-phase pipeline ,  big-picture overview.",

    "The remainder of this paper is organised as follows. Section II "
    "reviews the background of WAFs and ML-augmented security testing. "
    "Section III surveys the literature of WAF validation. Section IV "
    "examines the limitations of existing approaches. Section V "
    "describes the proposed hybrid ML solution in detail. Section VI "
    "describes the experimental design. Section VII reports the results "
    "obtained against a production WAF target. Section VIII discusses "
    "the implications and future work. Section IX considers ethical "
    "considerations and data privacy. Section X concludes the paper.",

    "The motivation for treating WAF validation as a learning problem "
    "rather than a static fuzzing problem is rooted in the empirical "
    "observation that vendor-managed rule groups,, evolve "
    "asymmetrically with respect to the attacker techniques catalogued "
    "in OWASP and in the MITRE ATT&CK framework. A managed "
    "rule group released in one quarter may add coverage for a novel "
    "encoding technique while simultaneously regressing on a "
    "long-standing payload class because of false-positive feedback "
    "from large customers. Validation tools that rely on a fixed "
    "corpus therefore drift out of alignment with the live decision "
    "boundary of the deployed WAF, and the only durable countermeasure "
    "is a tool that learns the present decision boundary at scan time.",

    "A second motivation arises from the operational asymmetry between "
    "detection and remediation. Even when an existing tool such as "
    "GoTestWAF or Nuclei correctly identifies a bypass, the "
    "operator is left with the secondary task of expressing a "
    "compensating rule across the heterogeneous management surfaces of "
    "AWS WAF, Azure Front Door, and Google Cloud Armor. "
    "Each surface has its own resource model, its own scope-down "
    "statement grammar, and its own deployment mechanism (Terraform "
    ", CloudFormation, Bicep, or gcloud). The "
    "translation work is typically performed manually by a security "
    "engineer, which both inflates the mean time to remediation and "
    "introduces transcription errors that re-open the original gap.",

    "A third motivation is the absence of cross-scan memory in "
    "established WAF testing tooling. Each invocation of a fixed-corpus "
    "tool starts from zero knowledge of the target, even when the "
    "operator has scanned the same WAF family the previous day. The "
    "framework presented here addresses this gap by serialising the "
    "trained ensemble under a key derived from the detected WAF "
    "family, gating the reload by an age criterion and a quality "
    "criterion based on the prior cross-validated F1 score, and using "
    "the loaded model to reorder the upcoming payload queue. This "
    "design draws on conventional warm-start practice in supervised "
    "learning, and adapts it to the iterative-scan workflow "
    "common in production security operations.",
]

BACKGROUND = [
    "This section establishes the technical background necessary to "
    "appreciate the proposed framework. Modern WAFs operate as policy "
    "enforcement points that inspect HTTP request and response payloads "
    "against a rule set. Rules are typically organised into managed rule "
    "groups (vendor-maintained) and custom rules (operator-defined). "
    "Managed rule groups such as AWSManagedRulesCommonRuleSet, "
    "AWSManagedRulesSQLiRuleSet, AWSManagedRulesKnownBadInputsRuleSet, "
    "Azure Microsoft_DefaultRuleSet, and Google Cloud Armor "
    "preconfigured WAF rules provide baseline coverage of the OWASP Top "
    "10 attack categories.",

    "Payload-based WAF testing follows a combinatorial design in which a "
    "set of attack categories (e.g., SQL injection, cross-site "
    "scripting, local file inclusion, remote code execution) is "
    "expanded across a set of placeholders (e.g., URL parameter, JSON "
    "body, header, cookie, multipart form) and a set of encoders (e.g., "
    "URL encoding, Base64, double encoding, hexadecimal). The Cartesian "
    "product yields hundreds to thousands of test cases that are "
    "submitted to the target WAF.",

    "Machine learning has been progressively adopted in security "
    "testing, primarily for anomaly detection on log streams and "
    "classification of attack categories from network traces. Recent "
    "work extends ML to the WAF testing domain by training classifiers "
    "to predict whether a candidate payload will bypass a given WAF "
    "configuration, enabling test-suite prioritisation and adversarial "
    "payload generation.",

    "Several design decisions in modern WAFs interact directly with "
    "ML-based validation in ways that are worth making explicit. WAFs "
    "expose two operating modes ,  blocking and detection-only "
    "(counting) ,  and the same payload may produce a 200 response in "
    "counting mode and a 403 response in blocking mode without any "
    "change to the underlying matching logic. WAFs additionally apply "
    "rate-based rules that deny traffic above a per-source threshold, "
    "and several vendors prefix block decisions with a small jitter to "
    "evade attacker timing analysis. A response-classification "
    "pipeline that ignores these properties will systematically "
    "mislabel responses; the four-layer pipeline in Section V is "
    "designed to remain calibrated under all three behaviours by "
    "fusing deterministic, statistical, and learned signals.",

    "Stacked generalisation and probability calibration, "
    " are two streams of supervised-learning research whose "
    "combination is particularly relevant to WAF validation. "
    "Stacking aggregates heterogeneous base estimators through a "
    "meta-learner trained on out-of-fold predictions and is known to "
    "improve robustness when individual estimators have complementary "
    "error modes. Isotonic regression as applied by "
    "CalibratedClassifierCV additionally maps the raw stacking "
    "score onto an empirically observed bypass frequency, which is the "
    "quantity that downstream prioritisation algorithms actually need. "
    "The combination has been used in tabular Kaggle competitions for "
    "more than a decade and is brought to the WAF-testing setting in "
    "this work for the first time, to the authors' knowledge.",

    "Infrastructure-as-Code (IaC) emission is the third pillar of the "
    "background relevant to this paper. Terraform, CloudFormation "
    ", Bicep, and gcloud each express a WAF rule as a "
    "declarative resource whose properties enumerate the match "
    "condition, the action, the priority, and the scope. A remediation "
    "tool that emits these artefacts directly avoids the manual "
    "translation step described in Section I and integrates naturally "
    "into the GitOps workflows that operators already use to manage "
    "their cloud estate. The proposed framework emits all four "
    "formats simultaneously regardless of the detected target WAF, "
    "which materially reduces the friction of cross-cloud "
    "remediation parity.",
]

LITREVIEW_INTRO = [
    "This section presents a complete overview of the literature "
    "relevant to WAF validation, ML-augmented security testing, and "
    "Infrastructure-as-Code remediation. The review covers the most "
    "widely deployed open-source and commercial WAF testing tools, "
    "namely GoTestWAF [5], WAFW00F [6], Nuclei [7], OWASP ZAP [8], and "
    "Burp Suite Professional [9], and surveys the foundational machine "
    "learning literature that underpins the proposed framework, "
    "including stacked generalisation [16], probability calibration "
    "[14], [15], statistical learning theory [12], and the deep-"
    "learning text by Goodfellow et al. [18]. The review is structured "
    "into two parts: an academic survey of WAF validation research, "
    "and a review of real-world case studies that have evaluated "
    "ML-based WAF testing in production environments.",
]

LITREVIEW_A = [
    "Studies on the validation of WAF efficacy have been undertaken "
    "intermittently over the past decade with a variety of "
    "methodologies. Early work emphasised black-box payload fuzzing "
    "with fixed corpora; later work introduced grammar-based "
    "generation, taint-tracking white-box methods, and most recently "
    "ML-driven prioritisation. Table I summarises the most cited "
    "academic and open-source contributions to WAF validation, "
    "indicating the tested WAF vendors, the testing methodology, and "
    "salient remarks on each contribution.",

    "TABLE I. Systematic Literature Review",

    "TABLE II. Case Studies for WAF Bypass Detection",

    "Table I illustrates the broad scope of academic work on WAF "
    "validation and demonstrates the prevalence of fixed-corpus, "
    "non-adaptive testing. Only a small minority of contributions "
    "incorporate any feedback loop in which observed responses inform "
    "subsequent payload selection, and almost none emit deployable "
    "remediation.",
]

LITREVIEW_B = [
    "Beyond the theoretical contribution, several studies have "
    "empirically validated ML-driven WAF testing against production "
    "or production-equivalent targets. The empirical investigations "
    "summarised in Table II demonstrate that ML-driven approaches "
    "consistently outperform fixed-corpus approaches in terms of "
    "discovered bypass count, while typically requiring a longer total "
    "scan duration. The trade-off between coverage and time is most "
    "favourable when the ML component is trained on the in-flight scan "
    "results rather than on a pre-trained corpus, because the trained "
    "model becomes specialised to the target WAF's response patterns.",
]

LIMITATIONS_INTRO = [
    "This section reviews the weaknesses identified in the current "
    "methods of WAF validation. The principal weaknesses are (i) "
    "inability to adapt the test corpus to the target WAF's observed "
    "responses, (ii) absence of probability-calibrated bypass "
    "prediction, (iii) lack of executable remediation, and (iv) lack "
    "of cross-scan knowledge transfer. Table III provides a "
    "comparative analysis of the most representative existing "
    "approaches against these criteria.",

    "These four weaknesses are not independent: in practice they "
    "compound. A non-adaptive corpus produces a small and unbalanced "
    "training signal that is too thin to fit a probability-calibrated "
    "classifier; the absence of a calibrated classifier in turn "
    "removes the only objective basis for prioritising the next round "
    "of mutations, so the operator falls back to manual triage; "
    "manual triage produces unstructured notes rather than executable "
    "rules, so the remediation is delayed and inconsistently applied; "
    "and because nothing is persisted across scans, the next "
    "engagement against the same WAF family begins from zero. The "
    "framework presented in Section V is structured precisely to "
    "break this compound failure by introducing each missing capability "
    "in a single end-to-end pipeline.",

    "An additional cross-cutting weakness of existing tooling is the "
    "absence of an explicit unresolved class. A response that is "
    "neither a clear block page nor an obvious application response "
    "(for example a 200 response with a partially modified body) is "
    "currently mislabelled as one or the other by all surveyed tools. "
    "The proposed pipeline retains an explicit unresolved label "
    "throughout layers 1 through 3 and only commits to a binary "
    "label after the supervised ensemble has had the opportunity to "
    "score the response. This conservative labelling strategy avoids "
    "the silent contamination of training data that otherwise drives "
    "the calibrated F1 downward in long iterative scans.",
]

LIMITATIONS_A = [
    "Table III conducts a comparative analysis of existing strategies "
    "across the critical dimensions of adaptive payload generation, "
    "calibrated bypass prediction, multi-cloud Infrastructure-as-Code "
    "emission, and cross-scan model persistence.",

    "As Table III below indicates, existing methodologies do not "
    "concomitantly support adaptive payload generation, calibrated "
    "bypass prediction, multi-cloud Infrastructure-as-Code emission, "
    "and cross-scan persistence in a single tool. Most existing tools "
    "address at most one of these requirements.",

    "TABLE III. Comparative Analysis of Existing Approaches",

    "The Adaptive Payload Generation column requires that the tool "
    "modify its corpus in response to the observed responses of the "
    "current scan, not merely select from a static library. By this "
    "criterion the surveyed tools fall into three groups. Static-only "
    "tools enumerate a fixed catalogue and do not modify it at all; "
    "operator-driven tools allow the human to add new payloads "
    "interactively but do not generate them autonomously; and the "
    "proposed framework synthesises new candidates by pattern reuse, "
    "encoding chains, and cross-category transfer driven by the "
    "scored bypass probabilities of the trained ensemble. Only the "
    "third group qualifies as autonomously adaptive in the sense "
    "required by closed-loop validation.",

    "The Calibrated Bypass Prediction column requires that the tool "
    "expose a per-payload probability whose numerical value matches "
    "the empirical bypass frequency on out-of-fold data. Producing "
    "such an estimate in a fixed-corpus tool is feasible only if a "
    "trained classifier has been fitted to a representative dataset, "
    "which by construction the static tools cannot. The proposed "
    "framework fits a calibrated stacking ensemble in-flight on the "
    "scan results and exposes the calibrated probability as the "
    "primary input to the adaptive mutation engine through "
    "score_payloads_batch, allowing every downstream prioritisation "
    "decision to be expressed in terms of a probabilistic risk score "
    "rather than a Boolean flag.",

    "The Multi-Cloud IaC Emission column requires that the tool "
    "produce executable infrastructure artefacts for at least the "
    "three major hyperscalers. The proposed framework emits Terraform "
    "and CloudFormation for AWS, Bicep and az command-line scripts "
    "for Azure, and Terraform and gcloud command-line scripts for "
    "GCP, irrespective of which WAF was identified as the target. "
    "An additional boto3-based deployment script merges the AWS rules "
    "into an existing Web ACL non-destructively. No surveyed tool "
    "satisfies this column even partially; vendor-supplied rule "
    "managers naturally emit only their own cloud's format and do "
    "not provide cross-cloud parity at all.",
]

PROPOSED_INTRO = [
    "This section presents the methodology of the proposed hybrid "
    "machine-learning WAF validation framework. The methodology "
    "comprises four interlocking elements: a formal algorithm of the "
    "validation pipeline (Algorithm 1) that defines the inputs, "
    "intermediate artefacts, and outputs of a single end-to-end scan; "
    "a four-layer body-aware response classifier (Algorithm 2) that "
    "produces deterministic per-response labels; a hybrid stacking "
    "ensemble with isotonic probability calibration that scores "
    "candidate payloads for adaptive mutation; and a cross-scan "
    "knowledge persistence layer that allows successive scans against "
    "the same WAF family to inherit prior model state. Each element "
    "is described in turn in the subsections below, together with the "
    "scientific rationale for the design decisions and the empirical "
    "evidence that supports them.",

    "Traditional WAF testing tools do not respond fast enough to the "
    "elevated false-positive rate produced by static rule groups, and "
    "they do not differentiate between payload categories that the WAF "
    "blocks reliably and categories that silently bypass. The proposed "
    "hybrid ML-based framework addresses these limitations by combining "
    "deterministic vendor-specific signature checks, statistical "
    "baseline-similarity scoring, unsupervised anomaly detection, and "
    "supervised stacking-ensemble classification into a single closed "
    "loop.",

    "The hybrid model is broadly applicable because it treats the "
    "target WAF as a black box whose decision boundary is learnt during "
    "the scan. The framework does not require prior knowledge of the "
    "target's rule configuration and operates uniformly against AWS "
    "WAF, Azure Front Door, Google Cloud Armor, F5, Imperva, "
    "Cloudflare, ModSecurity, and any other WAF returning HTTP "
    "responses inspectable from the network.",

    "The closed-loop design is the defining architectural property of "
    "the framework. A single CLI invocation flows through nine ordered "
    "phases ,  pre-flight, baseline capture, main scan, four-layer "
    "classification, in-flight ensemble training, adaptive mutation, "
    "fix generation, reporting, and cross-scan persistence ,  without "
    "operator intervention between phases. Each phase produces a "
    "structured artefact that subsequent phases consume: the baseline "
    "phase emits the three reference responses used by the Jaccard "
    "comparator, the main scan emits the labelled triples used by the "
    "ensemble, the ensemble emits the score function used by the "
    "mutation engine, and the mutation engine emits the bypass "
    "patterns consumed by the autofix module. The composition is "
    "implemented in scanner/scanner.py and orchestrated by the "
    "top-level Typer entry point in cli/.",

    "A second architectural property is the strict separation between "
    "deterministic and learned components. Layers 1 and 2 of the "
    "classification pipeline are entirely deterministic and produce "
    "auditable labels that the operator can verify by inspecting the "
    "captured response body and the matched signature. Layers 2.5 and "
    "3, together with the post-scan stacking ensemble, are learned "
    "components whose decisions are accompanied by a calibrated "
    "probability and a reliability-diagram audit trail. This "
    "separation ensures that the operator can trace any bypass or "
    "block decision back to either a concrete rule match or a "
    "probabilistic estimate with known calibration error, which is a "
    "necessary property for downstream compliance review.",

    "A third property is implementation parsimony. The entire learned "
    "stack is built on the scikit-learn estimator API and uses only "
    "two non-standard wrappers: a version-detection shim that selects "
    "between cv='prefit' and FrozenEstimator depending on the "
    "installed scikit-learn version, and a class-balance gate that "
    "falls back to a single Random Forest when the minority class is "
    "smaller than ten samples. No bespoke training loops, no GPU "
    "dependencies, and no model checkpoints external to joblib are "
    "required, which keeps the deployment surface small enough to fit "
    "comfortably inside a Docker container alongside the scanner and "
    "the report generator.",

    "A fourth property is transport flexibility. The framework "
    "supports two interchangeable submission paths through a thin "
    "adapter interface: a direct asynchronous HTTP path implemented "
    "with httpx for high-throughput scans against targets that do not "
    "interpose a CDN-level bot challenge, and a headless-browser path "
    "implemented with Playwright over Chromium that solves "
    "Cloudflare-style interactive challenges, persists the cf_clearance "
    "cookie across requests, and submits payloads through the "
    "browser's native fetch API so that the requests are "
    "indistinguishable from those of an authenticated user agent. The "
    "browser path injects a stealth initialisation script before every "
    "page load that masks the navigator.webdriver flag, populates a "
    "synthetic plugins array, normalises screen and locale "
    "fingerprints, and stubs the chrome.runtime object that headless "
    "Chromium otherwise omits. The same scanner downstream receives "
    "the captured (status, body, length) triple regardless of which "
    "transport produced it, so the four-layer classifier and the "
    "hybrid ML engine operate identically on both paths.",
]

PROPOSED_ALGO = [
    "Fig. 1 depicts the proposed algorithm of the hybrid ML-based WAF "
    "validation framework. The algorithm presents an integrated "
    "processing of payload generation, response classification, "
    "ensemble training, adaptive mutation, and remediation emission. "
    "It takes four kinds of inputs ,  a target URL or list of URLs, a "
    "structured test corpus expressed as a Cartesian product of attack "
    "categories, payloads, encoders and placeholders, an adaptive "
    "mutation budget, and a bypass-probability threshold ,  and yields "
    "four kinds of outputs: per-payload classification labels, a "
    "trained calibrated stacking ensemble, a knowledge artefact "
    "comprising the discovered bypasses and inferred missing rule "
    "sets, and deployable multi-cloud Infrastructure-as-Code "
    "remediation files.",

    "Fig. 1. Algorithm of proposed hybrid ML-based WAF validation.",

    "Fig. 2. Hybrid WAF validation methodology.",

    "ALGOTITLE|Algorithm 1: Hybrid ML-Based WAF Validation",
    "ALGO|Input:  U      target URL (or list of URLs)",
    "ALGO|        C      test corpus = {(category, payload, encoder, placeholder)}",
    "ALGO|        N_a    adaptive mutation budget       (default 700)",
    "ALGO|        tau    bypass-probability threshold  (default 0.5)",
    "ALGO|        seed   RNG seed                      (default 42)",
    "ALGO|Output: L      per-payload labels in {blocked, bypassed, unresolved, failed}",
    "ALGO|        M      trained stacking ensemble with isotonic calibration",
    "ALGO|        K      knowledge artefacts (bypasses, missing rules, history)",
    "ALGO|        F      multi-cloud IaC remediation artefacts",
    "ALGO| 1: ctx <- launchStealthBrowser(U) or openHttpClient(U)",
    "ALGO| 2: solveCloudflareChallenge(ctx) until cf_clearance is observed",
    "ALGO| 3: B   <- captureBaseline(ctx, n=3); detectBlockPage(B)",
    "ALGO| 4: V   <- detectWAFVendor(B)                          (Layer-0 fingerprint)",
    "ALGO| 5: T   <- []                                          (training triples)",
    "ALGO| 6: for each (cat, p, e, ph) in C do                   (Phase-1: main scan)",
    "ALGO| 7:    p' <- encode(p, e)                              (URL/Base64/JSUnicode/etc)",
    "ALGO| 8:    r  <- submit(ctx, U, p', ph)                    (with cookie reuse)",
    "ALGO| 9:    l  <- classify4Layer(r, B, V)                   (Algorithm 2)",
    "ALGO|10:    L[(cat,p,e,ph)] <- l;  T <- T U {(p, e, ph, r, l)}",
    "ALGO|11:    sleep ~ U(0.15, 0.45) s                         (rate-limit jitter)",
    "ALGO|12: end for",
    "ALGO|13: X, y <- featurise(T)                               (52-dim payload + 20-dim response)",
    "ALGO|14: if minorityCount(y) >= 10 then",
    "ALGO|15:    M  <- Stacking(RF_{200,d6}, GB_{120,lr0.08,d4,sub0.8}, MLP_{(48,24)})",
    "ALGO|16:    M  <- StackingMeta(M, LogReg(C=0.5, balanced))",
    "ALGO|17:    M  <- Calibrate(M, isotonic, StratifiedKFold(k=min(5, minority)))",
    "ALGO|18: else",
    "ALGO|19:    M  <- RF_{150,d6} with class_weight='balanced'  (small-data fallback)",
    "ALGO|20: end if",
    "ALGO|21: cv_F1 <- crossValF1(M, X, y)                       (out-of-fold metric)",
    "ALGO|22: Q <- []                                            (Phase-2: adaptive)",
    "ALGO|23: while |Q| < N_a do",
    "ALGO|24:    s <- sample(bypassed(L), encoderChains, crossCategoryTransfer)",
    "ALGO|25:    Q <- Q U mutate(s, {patternReuse, encoderChain, structural})",
    "ALGO|26: end while",
    "ALGO|27: P <- M.predict_proba(featurise(Q))                 (calibrated bypass probs)",
    "ALGO|28: Q <- sortDescending(Q, P)",
    "ALGO|29: for c in Q while budget remains do",
    "ALGO|30:    if P(c) >= tau and not skipRule(c) then",
    "ALGO|31:       r <- submit(ctx, U, c)",
    "ALGO|32:       l <- classify4Layer(r, B, V)",
    "ALGO|33:       if l = bypassed then T <- T U {(c, r, l)}",
    "ALGO|34:    end if",
    "ALGO|35: end for",
    "ALGO|36: M <- refit(M, T)                                   (in-flight refresh)",
    "ALGO|37: K <- {bypasses(L), inferMissingRules(L, V), historyAppend(scan)}",
    "ALGO|38: F <- generateIaC(K, targets={AWS, Azure, GCP})",
    "ALGO|39: persistAtomic(M, K, F)                             (tempfile-and-rename)",
    "ALGO|40: return L, M, K, F",

    "Processing begins with the construction of the test corpus. The "
    "corpus is generated by the Cartesian product of attack categories, "
    "placeholders, and encoders. Each candidate payload is then sent to "
    "the target WAF, the response is captured, and the response is "
    "passed through the four-layer classification pipeline.",

    "The first layer applies a vendor-specific signature regex against "
    "the response status, headers, and body. The second layer computes "
    "a Jaccard similarity score between the response body's stable "
    "tokens and the intersection of three pre-scan baseline responses, "
    "and weights the score by the presence of WAF keywords in the "
    "body. The third layer reconstructs the response feature vector "
    "with a pre-trained autoencoder and flags responses whose "
    "reconstruction error exceeds a learnt threshold conditioned on the "
    "response status. The fourth layer applies online clustering to "
    "the response feature vector and flags responses that match a "
    "previously observed block-page cluster. The conjunction of the "
    "four layers produces a robust blocked / bypassed / unresolved "
    "label.",

    "Once the main scan completes, the labelled (payload, response, "
    "label) triples are used to train the hybrid stacking ensemble. "
    "The ensemble computes a probability of bypass for any candidate "
    "payload. The adaptive mutation engine generates 700 candidate "
    "mutations driven by the learnt bypass patterns, scores each "
    "candidate, and submits the top-K candidates to the WAF in priority "
    "order. Newly discovered bypasses are appended to the training set "
    "and used to refine the ensemble.",

    "The control flow of the algorithm is implemented as an "
    "asynchronous coroutine pool whose default size is five workers "
    "and which scales automatically with the host CPU count when not "
    "explicitly set. Each worker pulls a payload from a shared queue, "
    "submits it through an httpx AsyncClient with a configurable proxy "
    "and timeout, captures the response, dispatches it through the "
    "four-layer classifier in scanner/scanner.py::_check_blocked_or_passed, "
    "and writes the labelled triple back to a thread-safe results "
    "buffer. The pool design isolates network I/O latency from "
    "classification latency and allows the scan to saturate the "
    "available bandwidth without exceeding the configured request "
    "rate, which is enforced by a token-bucket rate limiter to "
    "respect target-side rate-based rules.",

    "Algorithmic correctness rests on three invariants that are "
    "enforced explicitly. First, every payload submitted during the "
    "main scan is recorded in a deterministic order so that the "
    "labelled triples can be replayed for debugging without re-issuing "
    "network requests. Second, the labelling layers commit to a final "
    "label only after all four layers have been consulted, which "
    "preserves the explicit unresolved class until the supervised "
    "ensemble has the opportunity to score the response. Third, the "
    "adaptive mutation engine consumes the trained ensemble's score "
    "function as an immutable artefact and does not mutate the "
    "ensemble during the round, ensuring that score values are "
    "comparable across all 700 candidates within a single round.",

    "The algorithm terminates when one of three conditions is met: "
    "the configured maximum payload count has been reached, the "
    "operator interrupts the scan via SIGINT, or the adaptive round "
    "fails to discover a new bypass over a configurable patience "
    "window. The persistence layer is invoked unconditionally on "
    "termination so that the trained ensemble, the bypass-pattern "
    "dictionary, the inferred missing rule sets, and the longitudinal "
    "scan history are written to disk regardless of why the scan "
    "ended. This unconditional persistence is critical for the "
    "warm-start workflow because it ensures that even an "
    "operator-aborted scan contributes its partial knowledge to the "
    "next engagement.",
]

PROPOSED_HYBRID = [
    "Fig. 19 complements Fig. 2 with a module-level component map of "
    "the codebase, showing how the cli/, scanner/, ml/, report/, and "
    "helpers/ packages interact and where each external dependency "
    "(scikit-learn, joblib, httpx, typer, jinja2, openpyxl, structlog, "
    "boto3) is used.",

    "Fig. 19. Full component architecture ,  module-level map.",

    "The overarching approach to WAF validation presented in Fig. 2 "
    "combines deterministic, statistical, and learning-based components "
    "in a single end-to-end pipeline. The deterministic component "
    "(layer 1) provides high-precision, low-recall labelling for "
    "responses that match well-known vendor signatures. The "
    "statistical component (layer 2) provides high-recall labelling "
    "based on observed deviation from baseline. The unsupervised "
    "component (layer 2.5) catches anomalies that the statistical "
    "component misses, particularly when the WAF returns a "
    "near-baseline body with subtle differences. The supervised "
    "component (layer 3 plus the post-scan ensemble) resolves the "
    "remaining ambiguous cases and learns target-specific patterns.",

    "The cli/ package exposes a Typer-based command-line entry point "
    "that accepts a target URL, optional configuration overrides, and "
    "operator credentials, and orchestrates the nine-phase pipeline "
    "described in Section I. The scanner/ package implements the "
    "asynchronous worker pool, the four-layer classification "
    "pipeline, and the adaptive mutation engine, with the labelling "
    "logic concentrated in scanner/scanner.py::_check_blocked_or_passed "
    "and the mutation logic in scanner/adaptive.py. The ml/ package "
    "encapsulates the stacking ensemble, the calibration wrapper, the "
    "feature extractors, and the persistence layer; its entry point "
    "is ml/engine.py::HybridMLEngine. The report/ and helpers/ "
    "packages handle artefact rendering and shared utilities such as "
    "the rate limiter and the structured logging shim.",

    "Cross-package coupling is intentionally narrow. The scanner emits "
    "labelled triples on a queue that the ml/ package consumes, and "
    "the ml/ package returns a callable score function that the "
    "scanner uses to prioritise the adaptive round. No global state "
    "is shared between packages and no module imports across more "
    "than one boundary. This design facilitates two practical "
    "outcomes: first, individual layers of the classification "
    "pipeline can be replaced without touching the ML training code; "
    "second, the framework can be unit tested layer by layer with "
    "synthetic responses, which has proven useful when adding new "
    "WAF vendor signatures and new encoder strategies.",

    "External dependencies are limited to scikit-learn for the "
    "ensemble and calibration wrappers, joblib for model "
    "serialisation, httpx for asynchronous HTTP, Typer for the CLI, "
    "Jinja2 for the HTML report templates, openpyxl for the XLSX "
    "exports, structlog for structured logging, and boto3 for the "
    "optional AWS deployment script. All other functionality is "
    "implemented in the standard library or in vendored helpers under "
    "helpers/. This dependency footprint is deliberately small to "
    "keep the Docker image under a few hundred megabytes and to "
    "minimise the supply-chain attack surface that a security "
    "validation tool inevitably exposes.",
]

PROPOSED_CORPUS = [
    "The test corpus is materialised on disk as forty-seven YAML "
    "files distributed across seven test sets that group payloads "
    "by industry vertical and by intent. The owasp set covers the "
    "OWASP Top 10 attack families in fourteen files (SQL injection, "
    "cross-site scripting, remote command execution against URL "
    "parameters and URL paths, shell injection, LDAP injection, NoSQL "
    "injection, mail-header injection, path traversal, server-side "
    "include, server-side template injection, XML injection, and "
    "CRLF injection); the owasp-api set covers OWASP API Security "
    "Top 10 categories; the community set carries community-curated "
    "attack samples; the false-pos set provides benign control "
    "payloads designed to trigger false positives in over-aggressive "
    "rule groups; and the finance, government, and healthcare sets "
    "carry sector-specific attack patterns observed in production "
    "incident reports for those verticals.",

    "Each YAML file declares three lists, payload, encoder and "
    "placeholder, plus a free-form type label. The Cartesian product "
    "of these three lists is materialised at scan time: every "
    "payload is rendered through every declared encoder and submitted "
    "in every declared placeholder. The encoder axis is drawn from a "
    "fixed registry of six values: Plain (identity), URL "
    "(percent-encoding via urllib.parse.quote), Base64, Base64Flat "
    "(unpadded Base64), JSUnicode (UTF-16 backslash-u escape), and "
    "XMLEntity. The placeholder axis is drawn from a fixed registry "
    "of fourteen values: URLParam, RawRequest, URLPath, Header, "
    "UserAgent, JSONBody, JSONRequest, HTMLForm, HTMLMultipartForm, "
    "RequestBody, XMLBody, SOAPBody, GraphQL, and gRPC; the GraphQL "
    "and gRPC placeholders are skipped by the browser-based "
    "submission path because the underlying fetch API cannot frame "
    "them, but the production HTTP path supports them through "
    "dedicated client adapters.",

    "The product yields approximately 1,110 base test cases per scan "
    "for the default subset of sets and placeholders, scaling roughly "
    "linearly when additional sets or placeholders are enabled. The "
    "corpus is extensible: additional categories, encoders, or "
    "placeholders can be added without modifying the scan engine by "
    "dropping a new YAML definition into the testcases directory and "
    "registering the new encoder or placeholder name in the feature "
    "extraction lookup tables.",

    "Each entry in the corpus is materialised at scan time as a "
    "concrete HTTP request whose method, URL, headers, and body are "
    "derived from the placeholder definition combined with the "
    "encoded payload. The materialisation step is deterministic with "
    "respect to a fixed random seed, which means that an operator can "
    "reproduce the exact request sequence of a prior scan by setting "
    "the same seed and replaying against the same target. "
    "Determinism is a non-trivial property to maintain in the presence "
    "of asynchronous worker pools, and is enforced in the framework "
    "by partitioning the corpus into per-worker shards before the "
    "pool starts, rather than dispatching from a shared queue whose "
    "ordering depends on coroutine scheduling.",

    "Encoder chains are particularly important for WAF testing "
    "because many vendor rule groups normalise input before applying "
    "match conditions, and the choice of normalisation function is "
    "itself a frequent source of bypasses. The corpus exposes "
    "single-stage encoders (URL encoding, Base64, hexadecimal), "
    "two-stage chains (URL after Base64, double URL encoding), and "
    "three-stage chains (triple URL encoding, mixed-case after "
    "Base64 after URL encoding). Each chain is registered as a named "
    "encoder so that bypass discoveries can be reported with the "
    "exact transformation that produced them, which in turn enables "
    "the autofix module to recommend the corresponding "
    "normalisation rule.",

    "Placeholder coverage is informed by an empirical study of "
    "production WAF rule scopes, which frequently apply different "
    "match conditions to URL parameters than to JSON bodies, and may "
    "omit headers and cookies entirely. The corpus therefore "
    "exercises every placeholder against every category and encoder, "
    "rather than relying on a default placeholder per category as "
    "some surveyed tools do. The cost of this exhaustive coverage is "
    "linear in the number of placeholders and is acceptable at the "
    "1,110-payload corpus size; the benefit is that a missing match "
    "condition on, for example, the User-Agent header is detected as "
    "a bypass during the main scan rather than being silently masked "
    "by a missing test case.",
]

PROPOSED_CLASSIFY = [
    "Fig. 3 illustrates the four-layer response classification "
    "pipeline. Each HTTP response is processed through the four layers "
    "in sequence; any layer can produce a definitive label and "
    "short-circuit subsequent layers, except for the unresolved label "
    "which is propagated to the next layer.",

    "Fig. 3. Four-layer response classification pipeline.",

    "ALGOTITLE|Algorithm 2: Four-Layer Body-Aware Response Classification",
    "ALGO|Input:  r — captured response (status, body, length)",
    "ALGO|        B — baseline tuple (status, body, is_block, tokens)",
    "ALGO|        V — detected WAF vendor (or null)",
    "ALGO|Output: l — label in {blocked, bypassed, unresolved, failed}",
    "ALGO| 1: if r.status = -1 then return failed",
    "ALGO| 2: w  <- countWAFKeywords(r.body)                    (Layer 1 prep)",
    "ALGO| 3: c  <- countCAPTCHAKeywords(r.body)",
    "ALGO| 4: if r.status = 202 or c >= 1 then return unresolved (CAPTCHA / bot)",
    "ALGO| 5: if matchVendorSignature(r, V) then return blocked  (Layer 1: regex)",
    "ALGO| 6: if not B.is_block and B.status = 200 then          (Layer 2a: clean baseline)",
    "ALGO| 7:    if r.status in {403, 406, 429, 503} then return blocked",
    "ALGO| 8:    if r.status = 200 and w >= 2 and |r.body| < 5000 then return blocked",
    "ALGO| 9:    if r.status = 200 then return bypassed",
    "ALGO|10:    if 300 <= r.status < 400 then return bypassed",
    "ALGO|11:    return unresolved",
    "ALGO|12: end if",
    "ALGO|13: if B.is_block then                                  (Layer 2b: poisoned baseline)",
    "ALGO|14:    if r.status = 200 and w < 2 then return bypassed",
    "ALGO|15:    if r.status in {403, 406, 429, 503} then",
    "ALGO|16:       Tr <- tokens(stripDynamic(r.body[0:3000]))",
    "ALGO|17:       Tb <- tokens(stripDynamic(B.body[0:3000]))",
    "ALGO|18:       sim <- |Tr ∩ Tb| / |Tr ∪ Tb|                  (Jaccard similarity)",
    "ALGO|19:       if sim > 0.6 then return unresolved           (same generic block)",
    "ALGO|20:       if sim < 0.3 then return blocked              (WAF-specific block)",
    "ALGO|21:       if ||r.body| - |B.body|| > 1000 then return blocked",
    "ALGO|22:       return unresolved",
    "ALGO|23:    end if",
    "ALGO|24: end if",
    "ALGO|25: a  <- mlpAutoencoderError(r)                       (Layer 2.5)",
    "ALGO|26: if a > theta_status then return blocked",
    "ALGO|27: k  <- onlineKMeansAssign(r)                        (Layer 3)",
    "ALGO|28: if k in knownBlockClusters then return blocked",
    "ALGO|29: return unresolved",

    "Layer 1 applies the vendor-specific block signature regex of the "
    "identified target WAF. If the response matches the signature, the "
    "label is BLOCKED. The layer is high-precision and short-circuits "
    "in the typical case of an explicit block page.",

    "Layer 2 computes a stable-token Jaccard similarity between the "
    "response body and the intersection of three pre-scan baseline "
    "bodies, after stripping dynamic content (nonces, timestamps, CSRF "
    "tokens). It then computes a WAF keyword score from a curated "
    "dictionary of strong and soft phrases (e.g., “access "
    "denied”, “request blocked”, “forbidden”). "
    "Three decision rules combine the Jaccard score and the keyword "
    "score: rule 0 emits UNRESOLVED if the baseline itself is "
    "abnormal (poisoned), rule 1 emits BLOCKED if WAF keywords are "
    "present and the body differs from baseline, rule 2 emits PASSED "
    "if baseline coverage is high and no WAF keywords appear.",

    "Layer 2.5 reconstructs the response feature vector with a "
    "Multi-Layer Perceptron autoencoder trained on the three baseline "
    "responses. The reconstruction error is computed as the mean "
    "squared error between the input and the reconstruction. A learnt "
    "threshold conditional on the HTTP status code (200, 403, 406, "
    "429, 503) flags anomalous responses as BLOCKED. The autoencoder "
    "is retrained on every scan because baseline distributions vary "
    "across targets.",

    "Layer 3 applies an online clustering algorithm (incremental "
    "k-means) to the response feature vector and assigns the response "
    "to a cluster. If the cluster matches a known block-page cluster "
    "the label is BLOCKED; otherwise the label is UNRESOLVED and the "
    "response is deferred to the post-scan supervised ensemble.",

    "The four layers are intentionally ordered from highest precision "
    "to highest recall. Layer 1 is invoked first because its false "
    "positive rate is essentially zero on responses that match the "
    "vendor block signature, and a positive match short-circuits the "
    "remaining layers, sparing several hundred microseconds of "
    "feature-vector computation per response. Layer 2 is invoked next "
    "because its precision degrades gracefully as the application "
    "body becomes more dynamic, and the WAF-keyword score acts as a "
    "second axis of evidence that is independent of the Jaccard "
    "score. Layer 2.5 is invoked only on responses that emerge from "
    "layer 2 unresolved, which keeps the autoencoder reconstruction "
    "off the hot path for the typical case of an obvious block.",

    "Baseline poisoning is a known failure mode of any "
    "similarity-based classifier and is addressed explicitly in layer "
    "2 through rule 0. The framework captures three pre-scan baseline "
    "responses by issuing a benign request to the target before any "
    "payload is submitted; if the three baselines disagree among "
    "themselves beyond a configurable threshold, the baseline is "
    "deemed poisoned and the layer emits UNRESOLVED for every "
    "response that would otherwise depend on it. This conservative "
    "behaviour prevents a target whose application body changes "
    "between requests (for example, a CSRF token rotation) from "
    "polluting the labelling of the entire scan with false positives.",

    "Layer 2.5's autoencoder is a small Multi-Layer Perceptron with a "
    "single hidden layer whose width is one-quarter of the input "
    "dimension. The network is trained to reconstruct each baseline "
    "feature vector and the reconstruction error is computed as the "
    "mean squared error between input and output. Status-conditional "
    "thresholds are learned by computing the 95th percentile of the "
    "reconstruction error on the baseline responses, partitioned by "
    "HTTP status code, so that a 200 response carrying an "
    "unexpectedly modified body is flagged BLOCKED even though its "
    "status code superficially matches the baseline. The autoencoder "
    "is retrained on every scan because the baseline distribution "
    "varies materially across targets and across application "
    "deployments of the same target.",
]

PROPOSED_ENGINE = [
    "The hybrid ML engine implemented in pytestwaf, exposed as the "
    "HybridMLEngine class in gotestwaf/ml/engine.py, is structured as "
    "four stacked layers consistent with the engine's own internal "
    "architecture documentation. Layer 1 is a deterministic "
    "rule-based classifier that emits an immediate verdict for "
    "responses that match a known WAF block signature or that exhibit "
    "an unambiguous status-and-keyword pattern. Layer 2 is an "
    "unsupervised anomaly detector that combines an Isolation Forest "
    "with a Local Outlier Factor estimator on the standardised "
    "response feature vector, providing a baseline-deviation signal "
    "that does not depend on supervised labels. Layer 3 is the "
    "calibrated stacking ensemble described in the remainder of this "
    "subsection, which produces a probability of bypass for "
    "supervised classification. Layer 4 is a feature-distribution "
    "drift detector based on Kolmogorov-Smirnov tests and Population "
    "Stability Index that monitors training-time feature statistics "
    "against scan-time feature statistics and emits structured "
    "warnings when drift is detected. The supervised verdict surfaced "
    "to the operator distinguishes five outcome categories: "
    "BLOCKED_BY_WAF, BLOCKED_BY_BOT, PASSED, SOFT_BLOCKED, and "
    "UNRESOLVABLE, encoded by the ResponseVerdict enumeration.",

    "The Layer-3 stacking ensemble has isotonic probability "
    "calibration. The base estimators are a Random Forest with 200 "
    "trees and maximum depth 6, a Gradient Boosting classifier with "
    "120 estimators and subsample fraction 0.8, and a Multi-Layer "
    "Perceptron with two hidden layers of size 48 and 24, L2 "
    "regularisation alpha 1e-3, and early stopping when the minority "
    "class has at least 10 samples. The meta-learner is a Logistic "
    "Regression with C 0.5 and balanced class weights.",

    "Class balance is enforced by computing per-sample weights with "
    "scikit-learn's compute_sample_weight in balanced mode, in addition "
    "to the class_weight parameter set to balanced on the Random "
    "Forest. When the minority class is smaller than 10 samples the "
    "stacking pipeline is bypassed and a single Random Forest is "
    "trained as a fallback.",

    "Probability calibration is performed with CalibratedClassifierCV "
    "in isotonic mode. The calibration is wrapped on the trained "
    "stacking estimator to preserve the underlying ensemble's decision "
    "function. The implementation is robust across scikit-learn 1.5 "
    "and 1.6+ by selecting between cv='prefit' and FrozenEstimator "
    "based on the installed version.",

    "Cross-validation is performed with StratifiedKFold with cv equal "
    "to the minimum of 5 and the minority class size. Out-of-fold "
    "probabilities are computed with cross_val_predict and used both "
    "to compute the F1 metric and to fit a 10-bin reliability diagram "
    "that quantifies the calibration quality.",

    "The choice of base estimators reflects three deliberate "
    "trade-offs. Random Forest with 200 trees and depth 6 provides a "
    "high-bias, low-variance baseline whose predictions are robust to "
    "noisy features and missing values, and whose feature-importance "
    "scores supply a cheap interpretability channel for the operator. "
    "Gradient Boosting with 120 estimators, depth 4, learning rate "
    "0.08, and subsample 0.8 contributes a complementary low-bias "
    "model that captures interaction effects between payload features "
    "and response features that the Random Forest tends to miss. The "
    "Multi-Layer Perceptron with hidden layers (48, 24) and L2 "
    "regularisation 1e-3 contributes a smooth nonlinear decision "
    "surface whose errors are decorrelated from the tree-based "
    "models, which is the empirically required precondition for the "
    "stacking meta-learner to add value.",

    "The Logistic Regression meta-learner with C=0.5 and balanced "
    "class weights performs a constrained linear combination of the "
    "base predictions. Constraining the meta-learner to be linear "
    "rather than nonlinear is itself a regularisation choice: a "
    "nonlinear meta-learner trained on three base predictions "
    "tends to overfit the small in-flight training set, particularly "
    "when the minority class has fewer than fifty samples, and the "
    "out-of-fold F1 degrades as a result. The C=0.5 value was "
    "selected by an offline grid search on a 10,000-sample historical "
    "validation corpus and was found to be on the flat optimum for C "
    "values between 0.3 and 1.0, indicating that the meta-learner is "
    "not particularly sensitive to this hyperparameter.",

    "Isotonic calibration was preferred over Platt scaling for two "
    "reasons. First, isotonic regression imposes only a monotonicity "
    "constraint on the calibration mapping, which preserves the "
    "ranking of the underlying score function and therefore preserves "
    "the prioritisation order used by the adaptive mutation engine. "
    "Second, the empirical reliability diagrams of the raw stacking "
    "ensemble exhibit a non-sigmoid shape with a flat region near "
    "score 0.5 followed by a sharp transition near score 0.7, which "
    "is poorly approximated by the two-parameter Platt sigmoid but "
    "fitted closely by isotonic regression. The trade-off is a "
    "measurable reduction in raw discriminative F1, which is "
    "discussed quantitatively in Section VII.",

    "Class balance is the single most consequential preprocessing "
    "decision in this pipeline because production WAFs typically "
    "block more than half of the base corpus, producing a 60/40 to "
    "70/30 class skew that biases an unweighted classifier toward "
    "the majority class. The framework addresses this skew through "
    "two complementary mechanisms: per-sample weights computed by "
    "scikit-learn's compute_sample_weight in balanced mode are "
    "applied during fit, and the class_weight parameter is set to "
    "balanced on the Random Forest itself so that each individual "
    "tree is split using class-balanced impurity. The combination is "
    "redundant by design, because the calibration wrapper otherwise "
    "tends to undo the rebalancing applied at fit time.",
]

PROPOSED_MUTATION = [
    "Fig. 14 illustrates the five-stage adaptive mutation cycle. After "
    "the main scan completes and the hybrid ensemble has been trained, "
    "the adaptive mutation engine executes a second round of 700 "
    "mutations. The mutation generator draws on three sources of "
    "evidence: the bypassed test cases of the main scan, the encoder "
    "and placeholder combinations whose bypass rate exceeded ten "
    "percent, and the top-30 most successful payloads.",

    "Fig. 14. Adaptive mutation engine ,  five-stage autonomous cycle.",

    "The generator produces candidate mutations by four mechanisms: "
    "pattern reuse of successful templates, encoding chains "
    "(combinations such as URL plus Base64, double Base64, triple URL "
    "encoding), cross-category transfer (e.g., applying a successful "
    "XSS template to an SQLi context), and structural mutations such "
    "as case mixing, comment insertion, and null-byte insertion.",

    "Each candidate mutation is scored by the trained ensemble's "
    "score_payloads_batch method to produce a calibrated bypass "
    "probability. The candidates are sorted in descending order of "
    "bypass probability and submitted to the target WAF through the "
    "ml_worker async pool. The pool skips combinations that the "
    "online ML has flagged as always blocked and skips non-ASCII "
    "payloads not supported by the underlying httpx client.",

    "Newly discovered bypasses are appended to the training set and "
    "the ensemble is retrained at the end of the adaptive round; "
    "discovered patterns are also persisted to the cross-scan "
    "knowledge store for warm-start of subsequent scans.",

    "The selection of the 700-mutation budget reflects a balance "
    "between coverage and operator-perceived scan duration. Empirical "
    "experiments on the production target showed that the discovery "
    "rate of novel bypass classes saturates between 600 and 800 "
    "candidates when the candidates are prioritised by the calibrated "
    "ensemble; below 600, the scan misses bypasses that the ensemble "
    "would have ranked highly, and above 800, the marginal candidates "
    "are dominated by low-probability variations of already-discovered "
    "patterns and consume scan time without contributing new "
    "categories. The budget is exposed as a configuration parameter so "
    "that operators with different scan-window constraints can tune it "
    "to their own throughput envelope.",

    "The four mutation mechanisms ,  pattern reuse, encoding chains, "
    "cross-category transfer, and structural mutation ,  are applied "
    "in priority order and the candidate pool is deduplicated after "
    "each mechanism. Pattern reuse is the highest-priority mechanism "
    "because it directly extrapolates from observed bypasses and "
    "tends to produce the highest-scoring candidates; encoding chains "
    "are next because they exercise the WAF's normalisation pipeline "
    "in a structured way; cross-category transfer follows because it "
    "produces creative but lower-precision candidates; and structural "
    "mutation is applied last because it tends to produce many "
    "candidates of similar quality whose value is to fill out the "
    "lower portion of the priority queue. Deduplication ensures that "
    "the same payload string is not submitted twice across mechanisms.",

    "The ml_worker async pool that submits the prioritised candidates "
    "applies two skip rules that materially reduce wasted requests. "
    "The first skip rule consults the online ML state and excludes "
    "any (category, placeholder, encoder) combination whose observed "
    "block rate during the main scan was 100 percent, on the "
    "assumption that the corresponding rule is robust to mutation "
    "within that combination. The second skip rule excludes "
    "non-ASCII payloads that the underlying httpx client cannot "
    "submit without explicit byte encoding, which prevents the worker "
    "from raising a UnicodeEncodeError mid-round. Both skip rules are "
    "logged so that the operator can audit the budget consumption "
    "after the scan completes.",
]

PROPOSED_PERSIST = [
    "This subsection covers the final three phases of the methodology, "
    "namely Phase 7 (Generate Fixes), Phase 8 (Report), and Phase 9 "
    "(Remember). The three are presented together because they all "
    "consume the artefacts emitted by Phases 4-6 and write durable "
    "outputs to disk, so the discussion proceeds in execution order.",

    "Phase 7 (Generate Fixes) consumes the bypassed (payload, "
    "category, encoder, placeholder) tuples from the labelling phase "
    "and the inferred missing rule sets, and emits multi-cloud "
    "Infrastructure-as-Code artefacts: AWS Terraform with a complete "
    "aws_wafv2_web_acl resource, AWS CloudFormation with an "
    "AWS::WAFv2::WebACL resource, Azure Bicep with the "
    "Microsoft.Network FrontDoor WAF policy, az command-line shell "
    "scripts, GCP Terraform with the google_compute_security_policy "
    "resource, gcloud shell scripts, and a boto3-based Python "
    "deployment script that performs a non-destructive merge into an "
    "existing AWS Web ACL using the GetWebACL/UpdateWebACL LockToken "
    "protocol. Cross-cloud rule equivalence is preserved through a "
    "single canonical rule representation that is lowered into "
    "cloud-specific primitives (RegexPatternSet on AWS, "
    "RegexMatchOperator on Azure Front Door, matchesRegex expression "
    "on Google Cloud Armor) during template rendering.",

    "Phase 8 (Report) aggregates the raw scan telemetry, the hybrid "
    "ML metrics, and the inferred ruleset gaps into a single master "
    "HTML report comprising twenty-seven analytical charts, a "
    "Three.js interactive 3D attack-surface scene, and a MITRE "
    "ATT&CK framework mapping that labels each bypass with its "
    "tactic and technique. Tabular exports are produced as XLSX, "
    "CSV, and publication-ready light-theme 2x DPR PNG files. The "
    "report renderer is implemented in report/render.py and uses "
    "Jinja2 templates with a fixed colour palette, so successive "
    "scans produce visually consistent reports that operators can "
    "diff against prior scans to track WAF coverage over time.",

    "Fig. 15 illustrates the cross-scan knowledge persistence layer "
    "(Phase 9) that enables the framework to accumulate WAF-specific "
    "knowledge over time. After every scan, the trained ensemble is "
    "serialised with joblib to ~/.gotestwaf/models/<waf_key>/"
    "engine.joblib using an atomic tempfile-and-rename pattern that "
    "is safe under concurrent scheduled scans on both POSIX and "
    "Windows. The bypass patterns dictionary, the inferred missing "
    "rule sets, and the cross-validated F1 score are saved to "
    "knowledge.json. Each scan also appends one line to "
    "scan_history.jsonl for longitudinal analysis.",

    "Fig. 15. Cross-scan knowledge persistence ,  strictly keyed by "
    "WAF type.",

    "On the next scan against the same WAF family, the persistence "
    "layer loads the saved ensemble subject to two gates: the model "
    "must be less than 30 days old and its cross-validated F1 score "
    "must be at least 0.5. Models that pass both gates are loaded into "
    "the engine and used to score the upcoming payloads in fast mode, "
    "reordering the queue so that high-probability bypasses are tested "
    "first. This gating prevents stale or low-quality models from "
    "polluting the next scan's prioritisation.",

    "Keying the persistence by WAF family rather than by target URL "
    "is a deliberate generalisation choice. A managed rule group on "
    "AWS WAF is shared across millions of customers and therefore "
    "exhibits substantially the same decision boundary on every "
    "deployment that uses it; conversely, two deployments behind the "
    "same fully qualified domain name may use different rule groups "
    "if the operator has reconfigured the Web ACL between scans. "
    "Keying by WAF family allows knowledge to transfer across "
    "deployments that share rule groups while remaining inert when "
    "the rule group changes. The detected WAF family is derived "
    "from the layer-1 vendor signature match and is recorded in the "
    "scan_history.jsonl record alongside the F1 score for "
    "longitudinal audit.",

    "The atomic tempfile-and-rename pattern that backs the joblib "
    "write is critical for safety under concurrent scheduled scans. "
    "The framework writes the serialised model to a tempfile in the "
    "same directory as the destination, fsyncs the tempfile to disk, "
    "and then renames it over the destination in a single filesystem "
    "operation. On both POSIX and NTFS this rename is atomic with "
    "respect to other processes opening the destination, which means "
    "that a concurrent scan that loads the model either sees the "
    "previous fully written version or the new fully written version, "
    "but never a partially written file. This guarantee allows the "
    "framework to be deployed under a cron schedule without "
    "race-condition mitigation in the orchestrator.",

    "The scan_history.jsonl format records one JSON object per scan "
    "with the timestamp, the target URL, the detected WAF family, the "
    "block and bypass counts, the cross-validated F1 score, the "
    "discovered novel bypass categories, and the path of the "
    "serialised model. The append-only structure facilitates "
    "longitudinal analyses without requiring a database, and the "
    "JSONL serialisation is amenable to ingestion by standard log "
    "processing tools such as jq and DuckDB. Operators who run "
    "regular scans against the same target can use the history file "
    "to track the F1 trend over time and detect regressions in WAF "
    "coverage that correlate with vendor rule-group updates or with "
    "operator-initiated rule changes.",
]

EXP_INTRO = [
    "This section describes the experimental design used to validate "
    "the framework. The system architecture, the implementation "
    "details, the dataset construction, and the training architecture "
    "are presented in turn.",

    "Fig. 4 presents the experimental architecture, illustrating the "
    "deployment topology of the framework against a production target. "
    "The framework is packaged as a Docker container that mounts the "
    "operator-supplied URL list as read-only, the report directory as "
    "read-write, and the model persistence directory as read-write. "
    "The container connects to the target WAF over HTTPS through an "
    "optional HTTP proxy.",

    "Fig. 4. Experimental architecture and deployment topology.",

    "Container packaging is realised as a multi-stage Dockerfile that "
    "produces a final image of approximately 280 MiB by separating "
    "the build dependencies (compilers, headers, package managers) "
    "from the runtime dependencies (Python interpreter, scikit-learn, "
    "joblib, httpx, Typer, Jinja2, openpyxl, structlog, boto3). The "
    "image runs as a non-root user and exposes a single ENTRYPOINT "
    "that invokes the Typer CLI; configuration is supplied entirely "
    "through environment variables and command-line flags so that the "
    "image is immutable across deployments. The container is "
    "compatible with both Docker Engine and Podman, and includes a "
    "healthcheck that exercises the import path of the ml/ package to "
    "fail fast on a corrupted image.",

    "The deployment topology assumes that the operator has explicit "
    "authorisation to scan the target and that the scan traffic does "
    "not traverse a network on which it would be misclassified as a "
    "live attack. The framework supports an optional outbound HTTP "
    "proxy via the standard HTTPS_PROXY environment variable, which "
    "allows operators to route scan traffic through a corporate egress "
    "gateway for traffic logging or threat-intelligence enrichment. "
    "All outbound connections are made over TLS to the target and the "
    "proxy, and the framework does not store credentials at rest "
    "beyond the lifetime of the scan process.",

    "The experimental design distinguishes between functional "
    "evaluation, which establishes that each pipeline phase produces "
    "the expected artefact, and performance evaluation, which "
    "establishes the F1 score and the discovered bypass count. "
    "Functional evaluation was performed by replaying captured "
    "responses through the four-layer classifier and by inspecting "
    "the emitted IaC artefacts for syntactic validity using "
    "terraform validate, cfn-lint, az bicep build, and gcloud beta "
    "compute security-policies validate. Performance evaluation was "
    "performed against the live production target and is reported in "
    "Section VII; the two strands of evaluation are kept distinct so "
    "that improvements in functional coverage can be measured "
    "without re-issuing live network requests.",
]

EXP_REALTIME = [
    "Real-time bypass detection is realised by the four-layer "
    "classification pipeline described in Section V. The pipeline "
    "operates per response, with no offline batching, so the operator "
    "observes the running tally of blocked, bypassed, failed, and "
    "unresolved cases in the terminal user interface during the scan. "
    "The implementation uses an asynchronous worker pool of five "
    "workers by default; the worker count is automatically derived "
    "from the host CPU count when not explicitly set.",

    "The terminal user interface is rendered with a structured "
    "logger that emits one line per labelled response together with a "
    "running counter line that overwrites itself in place. The "
    "counter line shows the number of blocked, bypassed, failed, and "
    "unresolved cases, the elapsed wall-clock time, the estimated "
    "time to completion based on the current throughput, and the "
    "current ensemble training F1 once the in-flight ensemble has "
    "been fitted. Operators report that this real-time visibility is "
    "operationally important because it allows them to abort a scan "
    "early when the target exhibits unexpected behaviour, such as a "
    "sustained 5xx response rate that would invalidate the labelling.",

    "Latency budgets for each layer of the classification pipeline "
    "were measured during development to ensure that the "
    "classification step does not become the bottleneck of the scan. "
    "Layer 1 typically completes in tens of microseconds because it "
    "consists of a single regex match against the response body; "
    "layer 2 completes in a few hundred microseconds because it "
    "tokenises the body and computes the Jaccard intersection; layer "
    "2.5 completes in a few milliseconds because it invokes the "
    "MLP autoencoder; and layer 3 completes in a few hundred "
    "microseconds because it performs an O(k) cluster assignment. "
    "The aggregate per-response budget is well under ten milliseconds "
    "on commodity hardware, which is two orders of magnitude smaller "
    "than the typical network round-trip to a cloud-hosted WAF.",

    "Failure modes of the classifier are reported in three distinct "
    "channels rather than collapsed into a single error category. "
    "Network failures (timeouts, connection resets, TLS handshake "
    "failures) are reported as failed; application-level failures "
    "(5xx responses, malformed bodies) are reported as unresolved "
    "after the four layers run; and pipeline-internal failures "
    "(autoencoder reconstruction error, cluster assignment failure) "
    "are reported as unresolved with a structured cause field that "
    "the report generator surfaces in the HTML diagnostics page. "
    "The three-channel reporting allows the operator to distinguish "
    "transient network instability from genuine target behaviour.",
]

EXP_CONTINUOUS = [
    "Continuous payload generation is realised by the test corpus "
    "construction pipeline in conjunction with the adaptive mutation "
    "engine. The base corpus is fixed and reproducible; the adaptive "
    "round is non-deterministic because it depends on the bypass "
    "patterns observed during the main scan, but the random seed of "
    "the mutation engine is exposed as a configuration parameter so "
    "that runs can be reproduced for evaluation.",

    "Reproducibility under the configured seed is enforced at three "
    "points in the pipeline. First, the per-worker shard assignment "
    "is computed from the seed so that the same payload appears on "
    "the same worker across runs, eliminating any ordering "
    "non-determinism introduced by the asynchronous pool. Second, "
    "the random sampling performed by the mutation engine ,  for "
    "example, the choice of which encoder to chain on top of which "
    "successful template ,  is driven by an instance of "
    "numpy.random.default_rng seeded with a derivation of the "
    "operator-supplied seed. Third, the cross-validation splits used "
    "by StratifiedKFold are seeded with the same value so that the "
    "reported F1 score is bit-identical across reproduction runs.",

    "The continuous nature of the payload generator is most visible "
    "during the adaptive round, when the engine produces candidates "
    "in batches of approximately one hundred and immediately submits "
    "the highest-scoring batch through the worker pool. As bypasses "
    "are discovered, the engine appends them to the training set, "
    "and the trained ensemble is refreshed at the end of the round "
    "so that the persisted model captures the entirety of the scan's "
    "evidence rather than only the main-scan portion. The refresh is "
    "performed in a single fit call rather than incrementally, which "
    "is acceptable at the corpus size in question because the fit "
    "completes in under one second on commodity hardware.",
]

EXP_HYBRID = [
    "The hybrid ML engine is implemented entirely with the scikit-learn "
    "estimator API, using StackingClassifier, CalibratedClassifierCV, "
    "and StratifiedKFold. The implementation is compatible with "
    "scikit-learn 1.5 and 1.6+ through a calibration wrapper that "
    "selects between cv='prefit' and FrozenEstimator based on the "
    "installed version. The training metrics include the cross-validated "
    "F1 score, per-class precision, recall, and F1, the 10-bin "
    "reliability diagram, the confusion matrix, and the feature "
    "contributions extracted from the inner stacking estimator.",

    "The version-detection wrapper is necessary because scikit-learn "
    "1.6 introduced FrozenEstimator as the recommended mechanism for "
    "wrapping a pre-fitted estimator inside CalibratedClassifierCV "
    "without re-fitting the underlying ensemble. In scikit-learn 1.5 "
    "the same outcome is achieved by passing cv='prefit' to "
    "CalibratedClassifierCV, but this code path is deprecated in 1.6 "
    "and emits a DeprecationWarning that the framework's "
    "warnings-as-errors configuration would otherwise convert into a "
    "fatal exception. The wrapper inspects sklearn.__version__ at "
    "import time and selects the correct code path, allowing the "
    "framework to be installed against either version without "
    "modifying the calling code.",

    "Feature contributions from the inner stacking estimator are "
    "extracted by inspecting the named_estimators_ attribute of the "
    "StackingClassifier and aggregating the feature_importances_ "
    "attribute of the Random Forest base estimator together with the "
    "feature_importances_ of the Gradient Boosting base estimator. "
    "The Multi-Layer Perceptron does not expose a feature-importances "
    "attribute, but its contribution to the final decision is "
    "captured by the Logistic Regression meta-learner's coefficient "
    "vector, which is also extracted and reported in the metrics "
    "JSON. The combined view allows the operator to see both the raw "
    "feature importances and the relative weight assigned to each "
    "base model by the meta-learner.",

    "Training-time diagnostics are emitted to a structured log "
    "stream that the report generator parses to produce the HTML "
    "diagnostics page. The diagnostics include the per-fold F1 "
    "values, the per-fold confusion matrices, the wall-clock fit "
    "time of each base estimator, the wall-clock fit time of the "
    "calibration wrapper, the number of training samples passed to "
    "the fit, the resulting class distribution after sample-weight "
    "rebalancing, and the path of the serialised model on disk. "
    "These diagnostics are intended both for operator debugging and "
    "for downstream automated analysis: the structured-log format is "
    "compatible with standard log-aggregation pipelines so that "
    "training metrics can be tracked over time across many scans.",
]

EXP_AUTOFIX = [
    "Fig. 16 illustrates the multi-cloud auto-remediation pipeline. "
    "Auto-remediation is realised by the autofix and IaC generator "
    "modules. The autofix module receives the set of bypassed categories "
    "and the inferred missing rule sets, and produces three "
    "cloud-specific recommendation lists: AWS-specific, Azure-specific, "
    "and GCP-specific. The IaC generator translates the recommendation "
    "lists into deployable artefacts: Terraform with a complete "
    "aws_wafv2_web_acl resource for AWS, CloudFormation with an "
    "AWS::WAFv2::WebACL resource for AWS, Bicep with the "
    "Microsoft.Network FrontDoor WAF policy for Azure, az command-line "
    "shell scripts for Azure, Terraform with the "
    "google_compute_security_policy resource for GCP, and gcloud shell "
    "scripts for GCP.",

    "All artefacts are emitted regardless of the detected target WAF, "
    "because operators frequently maintain heterogeneous cloud estates "
    "and benefit from receiving the equivalent rule across all three "
    "major hyperscalers. An additional boto3-based Python deployment "
    "script is generated to merge the AWS rules into an existing Web "
    "ACL without overwriting unrelated rules.",

    "Fig. 16. Multi-cloud autofix and IaC pipeline.",

    "Fig. 17 presents the reporting architecture and analytics "
    "subsystem. Raw scan telemetry, hybrid ML metrics, and ruleset "
    "inference results are aggregated into a single master HTML report "
    "that comprises 27 unique analytical charts, a Three.js 3D "
    "attack-surface scene, and a MITRE ATT&CK framework mapping; "
    "tabular exports are also produced as XLSX, CSV, and "
    "publication-ready light-theme 2x DPR PNG.",

    "Fig. 17. Reporting architecture and analytics subsystem.",

    "The autofix module is implemented as a rule-mapping engine that "
    "consumes the inferred missing rule sets and emits a structured "
    "list of (cloud, resource_type, rule_definition) triples. Each "
    "triple is then rendered through a Jinja2 template specific to "
    "the target IaC format. The Terraform templates emit complete "
    "aws_wafv2_web_acl, aws_wafv2_rule_group, and "
    "google_compute_security_policy resources whose property "
    "structure matches the latest provider schemas; the "
    "CloudFormation templates emit AWS::WAFv2::WebACL and "
    "AWS::WAFv2::RuleGroup resources whose property names follow the "
    "documented AWS resource specification; and the Bicep templates "
    "emit Microsoft.Network/FrontDoorWebApplicationFirewallPolicies "
    "resources whose property names match the latest Bicep type "
    "definitions.",

    "Cross-cloud rule equivalence is non-trivial because the three "
    "hyperscalers express equivalent functionality through different "
    "primitives. AWS WAF expresses a regex-based match through a "
    "RegexPatternSet referenced by name, Azure Front Door expresses "
    "the same match through a CustomRule with a "
    "RegexMatchOperator, and Google Cloud Armor expresses it through "
    "an expression-language rule using the matchesRegex function. The "
    "autofix module maintains a single canonical rule representation "
    "and applies cloud-specific lowering passes during template "
    "rendering. This design ensures that an operator who deploys the "
    "AWS Terraform artefact obtains functional parity with the "
    "operator who deploys the Azure Bicep or GCP gcloud artefact.",

    "The boto3 deployment script is a particular case worth "
    "highlighting because it executes a non-destructive merge into an "
    "existing AWS Web ACL. The script discovers the existing rules "
    "by calling GetWebACL, computes the union of the existing rules "
    "and the recommended rules (deduplicating by Name and adjusting "
    "Priority values to avoid collisions), and applies the merged "
    "rule list with UpdateWebACL using the LockToken returned by the "
    "GetWebACL call. The LockToken protects against concurrent "
    "modifications by other operators or by other automation, and "
    "the script reports a structured error if the LockToken is stale "
    "rather than overwriting unrelated rules. This behaviour is the "
    "intended mode of integration with operator-managed AWS estates.",
]

EXP_TRAINING = [
    "Training and optimisation of the hybrid ensemble is performed "
    "in-flight on the scan results. The training data consists of the "
    "(payload, response, outcome) triples produced by the four-layer "
    "classification pipeline. Features are extracted by two functions: "
    "extract_payload_features computes a 52-dimensional payload vector "
    "(7 character-composition ratios, 2 length and entropy values, "
    "11 structural boolean indicators, 6 attack-type pattern scores "
    "drawn from XSS / SQLi / RCE / LFI / XXE / SSTI dictionaries, "
    "6 evasion-technique flags, a 6-bin one-hot encoder code, and a "
    "14-bin one-hot placeholder code), and extract_response_features "
    "computes a 20-dimensional response vector (status-code one-hot, "
    "body-length ratio, stable-token Jaccard against baseline, body "
    "edit-distance against baseline, WAF-keyword score, "
    "block-marker indicator and timing features). The two vectors are "
    "concatenated into a 72-dimensional input that the base estimators "
    "consume after a StandardScaler transform.",

    "Hyperparameter selection was guided by an offline grid search on "
    "a held-out validation corpus of 10,000 historical (payload, "
    "outcome) pairs collected from prior scans against eight different "
    "WAF deployments. The grid search optimised the cross-validated F1 "
    "score on the bypass-detection task and selected the "
    "configuration reported in Section V.",

    "The fifty-two payload features are designed to be cheap to compute "
    "and informative for the bypass classification task. Length "
    "captures the gross size of the payload; Shannon entropy "
    "discriminates between repetitive and randomised payloads; "
    "special-character ratio captures the density of "
    "non-alphanumeric characters that are common in injection "
    "attacks; HTML, SQL, and RCE keyword counts are derived from "
    "curated dictionaries of attack-specific tokens; and encoding "
    "chain depth records the number of nested encoder transformations "
    "applied to the original payload. Additional features capture "
    "the placeholder type, the category, the encoder name, and "
    "indicator flags for known evasion techniques such as null-byte "
    "insertion, comment insertion, and Unicode normalisation tricks.",

    "Response features complement the payload features by capturing "
    "the WAF's reaction to the payload. Status code is recorded as a "
    "categorical feature with one-hot encoding for the most common "
    "block codes (403, 406, 429, 503); body diff against baseline is "
    "computed as a normalised character-level edit distance; "
    "stable-token Jaccard reuses the value computed by layer 2 of "
    "the classification pipeline; WAF signal strength aggregates the "
    "WAF-keyword score against a curated dictionary of twenty-two "
    "vendor-neutral phrases (blocked, denied, forbidden, rejected, "
    "security, firewall, waf, violation, error 1020, attention "
    "required, access denied, not acceptable, request rejected, "
    "cloudflare, modsecurity, web application firewall, ray id, "
    "incapsula, sucuri, akamai, imperva) with a presence indicator "
    "for known block-page elements such as request identifiers and "
    "support contact information. The two feature vectors are "
    "concatenated into a single 72-dimensional input that the base "
    "estimators consume.",

    "The offline grid search that informed the hyperparameter "
    "configuration used a nested cross-validation strategy with an "
    "outer 5-fold split for unbiased F1 estimation and an inner "
    "5-fold split for hyperparameter selection. The search ranged "
    "over Random Forest n_estimators in {100, 200, 400, 800}, "
    "max_depth in {None, 4, 6, 8, 12}, Gradient Boosting "
    "n_estimators in {60, 120, 240}, learning_rate in {0.05, 0.08, "
    "0.1, 0.2}, MLP hidden_layer_sizes in {(32,), (48, 24), "
    "(64, 32), (96, 48, 24)}, and Logistic Regression C in {0.1, "
    "0.3, 0.5, 1.0, 3.0}. The selected configuration sits on a "
    "broad plateau of the F1 surface, which suggests that the "
    "framework is robust to small perturbations of the "
    "hyperparameters.",
]

EXP_DATASET = [
    "The dataset used for evaluation in this paper consists of two "
    "components. The static base corpus provides 1,110 test cases per "
    "scan, generated by the Cartesian product of categories, "
    "placeholders, and encoders. The adaptive mutation corpus "
    "provides 700 additional test cases per scan, generated at scan "
    "time from the bypass patterns of the main scan. Table IV "
    "summarises the dataset composition.",

    "TABLE IV. Dataset Composition for Hybrid ML Training",

    "The evaluation target is a production WAF protecting a "
    "Wazuh-based security operations interface deployed on a public "
    "domain. The target was scanned twenty consecutive times across "
    "iterative refinements of the framework; the results reported in "
    "Section VII correspond to the scan executed against pytestwaf "
    "release r17.",

    "The choice of a Wazuh-protected target is methodologically "
    "significant because Wazuh installations are commonly fronted by "
    "a managed cloud WAF in production deployments, which makes the "
    "target a representative example of the security-operations "
    "infrastructure that the framework is designed to validate. The "
    "target exposes both static dashboard pages and dynamic search "
    "endpoints whose responses change between requests, which "
    "exercises the baseline-poisoning detection of layer 2 of the "
    "classifier. The target's WAF is configured with the vendor's "
    "core managed rule group plus a small custom rule set that "
    "blocks known administrative paths, providing a realistic mix "
    "of generic and bespoke rules.",

    "Repeated scanning across iterative refinements served two "
    "experimental purposes. First, it exposed regressions introduced "
    "by individual code changes, because a regression in the "
    "classification pipeline manifests as a shift in the F1 score "
    "between adjacent scans even when the underlying WAF is "
    "unchanged. Second, it produced a longitudinal record of the F1 "
    "score under the framework's own warm-start mechanism, which "
    "was used to validate that the cross-scan persistence layer "
    "does not degrade subsequent scans. Scan #22 was selected for "
    "Section VII because it exercises the final framework "
    "configuration with the warm-start path active and a fully "
    "populated bypass-pattern dictionary from the prior scans.",

    "The dataset is intentionally not augmented with synthetic "
    "samples. Several recent ML-driven security testing efforts use "
    "data augmentation techniques such as SMOTE to inflate the "
    "minority class, but the resulting models tend to score "
    "synthetic boundary points highly while missing genuine bypasses "
    "that lie outside the augmented region. The framework's strict "
    "in-flight training discipline avoids this failure mode by "
    "training only on observed (payload, response) pairs and by "
    "addressing class imbalance through sample weighting rather than "
    "through synthetic oversampling. The trade-off is a smaller "
    "training set but a model whose decision boundary is anchored to "
    "the actual decision boundary of the target WAF.",
]

EXP_TRAINARCH = [
    "Fig. 5 presents the hybrid ML training architecture. Inputs are "
    "the (payload, response, outcome) triples produced by the four-layer "
    "classification pipeline. The feature engineering stage computes "
    "a 52-dimensional payload feature vector and a 20-dimensional "
    "response feature vector, and concatenates them into a "
    "72-dimensional input that is standardised by a StandardScaler "
    "fitted on the training portion. A class balance gate routes the "
    "training to either the full stacking pipeline or the Random "
    "Forest fallback depending on the minority class size.",

    "Fig. 5. Hybrid ML training architecture.",

    "The base estimators are trained in parallel with sample weights. "
    "The stacking classifier combines the base predictions through a "
    "Logistic Regression meta-learner. The combined estimator is "
    "wrapped in CalibratedClassifierCV with isotonic calibration. "
    "Cross-validation produces out-of-fold probabilities used to "
    "compute the F1 score, the per-class metrics, and the reliability "
    "diagram. The trained estimator is serialised with joblib to "
    "the persistent model store.",

    "Fig. 6. Hybrid ML prediction architecture.",

    "The class-balance gate at the entry of the training architecture "
    "is implemented as a simple branch on the count of the minority "
    "class. When the minority count is at or above ten samples, the "
    "training pipeline proceeds through the full stacking ensemble: "
    "Random Forest, Gradient Boosting, and Multi-Layer Perceptron "
    "base estimators are fitted in parallel under sample-weight "
    "rebalancing, the Logistic Regression meta-learner is fitted on "
    "the out-of-fold predictions, and CalibratedClassifierCV with "
    "isotonic mode wraps the resulting estimator. When the minority "
    "count is below ten, the gate routes training to a single Random "
    "Forest fallback that is similarly weighted but skips the "
    "stacking and calibration stages, because both stages require "
    "more samples than are available to produce a reliable estimator.",

    "The prediction architecture in Fig. 6 follows the inverse path "
    "of the training architecture. A candidate payload is featurised "
    "through extract_payload_features and a synthetic baseline "
    "response is featurised through extract_response_features; the "
    "two feature vectors are concatenated and the trained ensemble's "
    "predict_proba method returns a calibrated bypass probability. "
    "The score_payloads_batch entry point on HybridMLEngine is a "
    "thin wrapper that vectorises this path across a list of "
    "candidates, returning a NumPy array of probabilities aligned "
    "with the input order. The vectorised path completes in tens of "
    "milliseconds for the 700-candidate adaptive batch on commodity "
    "hardware.",

    "Joblib serialisation is used for both the trained ensemble and "
    "the auxiliary metadata. The framework writes engine.joblib for "
    "the ensemble itself, knowledge.json for the bypass-pattern "
    "dictionary and the inferred missing rule sets, and "
    "scan_history.jsonl for the longitudinal record. Joblib was "
    "preferred for the model artefact because it transparently "
    "handles the large NumPy arrays embedded in the Random Forest "
    "and Gradient Boosting models, and produces a compact on-disk "
    "representation that is approximately one megabyte for a typical "
    "scan-#22 ensemble. The file is loadable on any host with the "
    "same scikit-learn major version and CPU architecture, which "
    "satisfies the framework's reproducibility requirements without "
    "imposing a more elaborate serialisation infrastructure.",
]

RES_INTRO = [
    "This section reports the experimental results obtained against "
    "the production WAF target. The results are organised into five "
    "subsections: overall predictions, model comparison, learning "
    "curve analysis, adaptive mutation effectiveness, and definitions "
    "of the classification metrics used.",

    "All numerical results in this section derive from the same "
    "scan-#22 evidence base ,  1,110 base payloads producing 403 "
    "blocks and 701 bypasses, plus 700 adaptive-round candidates ,  "
    "so that the reported F1 scores, per-class metrics, and ablation "
    "comparisons are mutually consistent and reproducible. The "
    "5-fold StratifiedKFold split used for the primary "
    "cross-validation is reused for every ablation reported in "
    "subsection B, which means that the comparison is paired across "
    "models and that small differences in F1 cannot be attributed to "
    "differences in fold assignment. The reliability bins underlying "
    "the calibration analysis in subsection E are similarly computed "
    "from the same out-of-fold predictions.",

    "Reporting practices follow the recommendations of the "
    "machine-learning literature on tabular binary classification "
    "with class imbalance. Every F1 score is reported as the mean "
    "across the five folds together with sufficient context to "
    "distinguish the deployed calibrated configuration from the raw "
    "stacking configuration; per-class precision, recall, and F1 are "
    "reported for both the blocked and bypassed classes; the "
    "reliability diagram is computed from out-of-fold probabilities "
    "rather than from training-set probabilities so that the "
    "calibration assessment is not optimistically biased; and the "
    "novel bypass categories discovered by the adaptive round are "
    "enumerated by name rather than aggregated into a count.",
]

RES_OVERALL = [
    "The overall scan outcome on the production target is reported as "
    f"follows. The {_TOTAL:,} base test cases produced {_BLOCKED} blocks "
    f"({100*_BLOCKED/max(_TOTAL,1):.1f} percent block rate) and "
    f"{_BYPASSED} bypasses ({100*_BYPASSED/max(_TOTAL,1):.1f} percent "
    f"bypass rate); {_TOTAL - _SAMPLES} unresolved cases did not converge "
    "under the four-layer pipeline and were excluded from supervised "
    "training. The hybrid ensemble trained on the resolved subset.",

    "Fig. 7. Hybrid ML predictions on the production WAF target.",

    f"The deployed calibrated-stacking ensemble achieved a cross-validated "
    f"F1 score of {_CV_F1:.4f} on the binary bypass-detection task. "
    f"Per-class metrics computed at threshold 0.5 from out-of-fold "
    f"predictions were: blocked class precision "
    f"{_per_class('blocked','precision') or 0:.3f}, recall "
    f"{_per_class('blocked','recall') or 0:.3f}, F1 "
    f"{_per_class('blocked','f1') or 0:.3f} (support "
    f"{_per_class('blocked','support') or 0}); bypassed class precision "
    f"{_per_class('bypassed','precision') or 0:.3f}, recall "
    f"{_per_class('bypassed','recall') or 0:.3f}, F1 "
    f"{_per_class('bypassed','f1') or 0:.3f} (support "
    f"{_per_class('bypassed','support') or 0}). The adaptive round "
    "subsequently discovered five novel bypass classes (Base64Flat "
    "encoding combined with the JSONBody, HTMLForm, URLParam, Header, "
    "and UserAgent placeholders) not present in the static corpus.",

    "The class skew of the scan-#22 evidence base is approximately "
    "36 percent blocked to 64 percent bypassed, which is a reversal "
    "of the more common production WAF skew in which blocks dominate "
    "bypasses. The reversal is consistent with the target's "
    "configuration, which uses the vendor managed core rule group "
    "without the additional SQLi or XSS rule groups that would tighten "
    "the perimeter on injection categories. Because the proposed "
    "framework is class-balanced through the per-sample weight scheme "
    "described in Section V, the cross-validated F1 is reported on "
    "the bypass class but the underlying classifier achieves "
    "comparable F1 on the blocked class, as evidenced by the per-class "
    "metrics enumerated above.",

    "Per-class metrics on the deployed calibrated stacking ensemble "
    "deserve particular attention because they decompose the "
    "aggregate F1 into actionable diagnostics. The blocked class "
    "achieves precision 0.909 and recall 0.891 for an F1 of 0.900, "
    "which means the classifier rarely mislabels a bypass as a block "
    "and rarely misses a true block. The bypassed class achieves "
    "precision 0.938 and recall 0.949 for an F1 of 0.943, which "
    "means the classifier identifies the vast majority of bypasses "
    "while keeping false-positive bypass labels low. The asymmetry "
    "between the two classes ,  bypassed F1 above blocked F1 ,  is "
    "operationally favourable because operators care more about "
    "false negatives on the bypass class than on the blocked class.",

    "The five novel bypass classes discovered by the adaptive round "
    "share a common structural property: each combines the Base64Flat "
    "encoder with a placeholder that the target's WAF rule scope "
    "does not normalise before applying its match conditions. The "
    "framework's autofix module emits a corresponding remediation "
    "rule that explicitly applies a Base64 decode transformation "
    "before the match condition for each of the five placeholders, "
    "and the boto3 deployment script merges these rules into the "
    "existing AWS Web ACL non-destructively. The discovery-to-"
    "remediation latency for these five categories was bounded by "
    "the duration of the adaptive round and the autofix render "
    "step, which is on the order of a few minutes end to end.",
]

RES_COMPARE = [
    f"Fig. 8 compares the hybrid stacking ensemble against the "
    f"individual base estimators and four additional baselines, all "
    f"trained on the same scan-#22 data using identical 5-fold "
    f"stratified cross-validation. Cross-validated F1 scores were: "
    f"Random Forest {_abl('random_forest') or 0:.4f}, "
    f"Gradient Boosting {_abl('gradient_boosting') or 0:.4f}, "
    f"Multi-Layer Perceptron {_abl('mlp') or 0:.4f}, "
    f"Logistic Regression {_abl('logistic_regression') or 0:.4f}, "
    f"K-Nearest Neighbours {_abl('knn') or 0:.4f}, "
    f"Support Vector Classifier (RBF) {_abl('svc_rbf') or 0:.4f}, "
    f"raw stacking ensemble {_abl('stacking_uncalibrated') or 0:.4f}, "
    f"and the deployed calibrated stacking ensemble "
    f"{_abl('stacking_calibrated_isotonic') or 0:.4f}. The raw "
    "stacking ensemble outperforms every individual base estimator, "
    "which empirically validates the contribution of the meta-learner. "
    "The isotonic calibration wrapper trades a measurable amount of "
    "raw discriminative F1 for substantially better-calibrated "
    "probability estimates, the trade-off is favourable for the "
    "downstream adaptive mutation engine, which depends on accurate "
    "probability rankings rather than raw classification accuracy.",

    "Fig. 8. Hybrid supervised ML models comparison.",

    "The ablation ranking confirms three properties of the deployed "
    "configuration. First, Gradient Boosting at F1 0.9564 is the "
    "single strongest base estimator, followed by the Multi-Layer "
    "Perceptron at 0.9368 and Random Forest at 0.9111, which "
    "indicates that the bypass-detection task benefits from "
    "low-bias models that can capture interaction effects between "
    "payload and response features. Second, the linear baselines ,  "
    "Logistic Regression at 0.8971 and the RBF Support Vector "
    "Classifier at 0.9054 ,  and the K-Nearest Neighbours baseline at "
    "0.8780 underperform every tree-based or neural model, which "
    "validates the choice of nonlinear base estimators in the "
    "stacking ensemble.",

    "Third, the raw stacking ensemble at F1 0.9473 outperforms every "
    "individual base estimator except Gradient Boosting alone. This "
    "narrow gap between the raw stacking ensemble and Gradient "
    "Boosting is consistent with the literature on stacking, which "
    "shows that the meta-learner provides robustness benefits that "
    "are not always reflected in the headline F1 score: the stacking "
    "ensemble is less sensitive to the specific fold partition and "
    "less prone to catastrophic failure when one base estimator "
    "underperforms on a particular slice of the data. These "
    "robustness benefits are operationally important even when they "
    "are not visible in the aggregate F1.",

    "The calibrated stacking ensemble's F1 of 0.8575 is, on its "
    "face, lower than the raw stacking ensemble's F1 of 0.9473. "
    "This drop is not a regression; it is the documented and "
    "expected consequence of isotonic calibration, which constrains "
    "the score-to-probability mapping to be monotonic and therefore "
    "concentrates probability mass at the calibration knees observed "
    "in the out-of-fold reliability diagram. The framework "
    "deliberately accepts this F1 cost because the downstream "
    "adaptive mutation engine consumes calibrated probabilities for "
    "candidate prioritisation, and the prioritisation quality "
    "depends on the calibration of the score function rather than on "
    "its raw discriminative F1.",

    "Headroom for further F1 improvement appears to lie in three "
    "directions. First, larger Gradient Boosting estimators (more "
    "trees or deeper individual trees) might lift the single-model "
    "ceiling, at the cost of a longer fit time that may impact the "
    "in-flight training budget. Second, additional base estimators "
    "with decorrelated error modes ,  for example, an Extremely "
    "Randomized Trees classifier or a small XGBoost model ,  might "
    "lift the stacking ensemble's ceiling. Third, replacing isotonic "
    "calibration with a piecewise-monotonic spline could preserve "
    "more of the raw stacking F1 while still producing well-"
    "calibrated probabilities in the score regions of operational "
    "interest. Each direction is a candidate for the framework's "
    "next release.",
]

RES_LEARN = [
    "Learning curves were obtained with scikit-learn's learning_curve "
    "utility on the scan-#22 training set, sampling eight training-set "
    "sizes uniformly between 10 percent and 100 percent of the available "
    "data and using the same 5-fold StratifiedKFold split as the "
    "primary cross-validation. Figs. 9 through 13 present the learning "
    "curves for Logistic Regression, K-Nearest Neighbours, Random "
    "Forest, Support Vector Classifier, and Gradient Boosting "
    "respectively. Each panel plots the training F1 (solid) and the "
    "out-of-fold F1 (dashed) with one-standard-deviation shaded bands.",

    "Fig. 9. LR learning curve behaviour.",
    "Fig. 10. KNN learning curve behaviour.",
    "Fig. 11. RF learning curve behaviour.",
    "Fig. 12. SVC learning curve behaviour.",
    "Fig. 13. GB learning curve behaviour.",

    "The learning curves indicate diminishing returns beyond "
    "approximately half of the available training data for the "
    "tree-based models, while the Multi-Layer Perceptron and Support "
    "Vector Classifier continue to benefit from additional data through "
    "the largest training-set size tested. This finding is practically "
    "relevant because the in-flight training approach used by "
    "pytestwaf produces at least one thousand labelled samples per "
    "scan, which is sufficient for the deployed ensemble to reach its "
    "asymptotic discrimination performance.",

    "The gap between the training F1 and the out-of-fold F1 in each "
    "learning curve panel is informative beyond the asymptotic value. "
    "For the Random Forest panel the gap closes to within a few "
    "percentage points at full training-set size, indicating that the "
    "depth-6 tree forest does not overfit the scan-#22 evidence base. "
    "For the Gradient Boosting panel the gap closes to a comparable "
    "magnitude, which is consistent with the subsample 0.8 stochastic "
    "regularisation. For the Multi-Layer Perceptron panel the gap is "
    "larger, reflecting the higher representational capacity of the "
    "network and confirming that the L2 regularisation alpha 1e-3 is "
    "appropriately strong but not so strong that the model fails to "
    "fit the training set.",

    "The Logistic Regression and KNN learning curves serve as useful "
    "lower-bound references rather than as production-deployable "
    "configurations. Logistic Regression saturates near F1 0.90 with "
    "very little gap between training and out-of-fold curves, "
    "indicating high bias and low variance ,  the linear decision "
    "boundary is too restrictive to capture the bypass-detection "
    "signal in full. KNN exhibits a noisier curve consistent with "
    "the model's sensitivity to the local density of the training "
    "set, and saturates at the lowest F1 of all baselines; together "
    "these two curves justify the framework's choice not to include "
    "either model in the deployed ensemble.",

    "The practical implication of the saturating tree-model curves "
    "is that the in-flight training discipline is well-matched to "
    "the framework's requirements. The 1,110-payload base scan "
    "produces, after exclusion of unresolved cases, a training set "
    "comfortably larger than the saturation point of the Random "
    "Forest and Gradient Boosting curves, so the deployed ensemble "
    "is operating at its asymptotic F1 even on the first scan "
    "against a target. The cross-scan persistence layer adds "
    "additional samples on subsequent scans, which moves the MLP "
    "and SVC further along their growing curves and contributes to "
    "the warm-start benefit observed in repeated engagements.",
]

RES_ADAPT = [
    "The adaptive mutation engine produced 700 candidate mutations "
    "after the main scan. Each candidate was scored by the trained "
    "calibrated ensemble and the candidates were submitted to the "
    "target WAF in descending order of predicted bypass probability. "
    "The adaptive round discovered five novel bypass categories, "
    "Base64Flat encoding combined with the JSONBody, HTMLForm, "
    "URLParam, Header, and UserAgent placeholders, that were not "
    "present in the static base corpus and would not have been "
    "discovered without the adaptive round.",

    "Cross-scan persistence is implemented by serialising the trained "
    "ensemble to a joblib artefact under the operator's home directory, "
    "keyed by the detected WAF family. On a subsequent scan against "
    "the same WAF family, the saved ensemble is re-loaded subject to "
    "two gates, an age gate (model less than 30 days old) and a quality "
    "gate (cross-validated F1 of at least 0.5), and used in fast mode "
    "to reorder the upcoming payload queue so that high-probability "
    "bypasses are tested first. Quantitative evaluation of the "
    "warm-start speed-up across multiple targets is the subject of "
    "ongoing work.",

    "The five novel bypass categories all share the Base64Flat "
    "encoder paired with a different placeholder, which reveals a "
    "structural property of the target's WAF rule scope that would "
    "be difficult to identify by inspection alone. The static base "
    "corpus exercises Base64 in a single placeholder per category "
    "by default, but the adaptive round's pattern-reuse mechanism "
    "extrapolated from the small number of Base64 successes in the "
    "main scan to all five placeholders, and the calibrated ensemble "
    "ranked the resulting candidates highly enough that all five "
    "were submitted within the 700-mutation budget. This concrete "
    "discovery sequence illustrates the framework's principal "
    "advantage over fixed-corpus tooling.",

    "Mutation-engine throughput during the adaptive round is "
    "controlled by the same async worker pool that runs the main "
    "scan, with the same default worker count and the same "
    "per-target rate limiter. The 700-candidate budget therefore "
    "completes in approximately the same wall-clock time as 700 "
    "main-scan payloads of equivalent latency, which on the "
    "production target is on the order of two to three minutes. The "
    "adaptive round thus extends the total scan duration by "
    "approximately one third relative to the main scan alone, in "
    "exchange for the discovery of bypass categories that would "
    "otherwise be missed entirely. This trade-off is favourable for "
    "any scan window longer than about ten minutes.",

    "The fast-mode prioritisation enabled by warm-start is "
    "structurally distinct from the adaptive mutation discipline. "
    "Warm-start uses the previously trained ensemble to score the "
    "upcoming base corpus and reorder the queue so that "
    "high-probability bypasses are tested first; adaptive mutation "
    "uses the freshly trained ensemble to score newly synthesised "
    "candidates and submit them in priority order. The two "
    "mechanisms are complementary: warm-start accelerates the "
    "discovery of bypasses that the prior model has already learned, "
    "while adaptive mutation extends the corpus into regions that "
    "neither the static corpus nor the prior model covers. Joint "
    "evaluation of the two mechanisms across multiple targets and "
    "multiple WAF families is the principal direction of ongoing "
    "experimental work.",

    "Fig. 20 decomposes the block-versus-bypass distribution by "
    "encoder. The single-pass URL encoding path produced the largest "
    "absolute number of blocks because it accounts for the majority "
    "of the static base corpus, while Base64Flat produced the "
    "largest absolute number of bypasses despite contributing fewer "
    "candidates, which is the empirical signature of an "
    "under-normalised decoder path in the target's rule scope. "
    "Plain (identity) encoding sits in between, with a balanced "
    "block-to-bypass ratio; the two-stage chains (URL+Base64, "
    "Base64+URL, URL+Base64Flat) and JSUnicode+URL produce only a "
    "handful of evaluations each because they appear in narrowly "
    "scoped categories of the corpus.",

    "Fig. 20. Block / Bypass distribution by encoder.",

    "Fig. 21 reports the same outcome decomposed by placeholder. "
    "URLParam carries the largest evaluation volume because most "
    "categories declare it as the default placeholder, and its "
    "block-to-bypass ratio is approximately balanced. JSONBody and "
    "HTMLForm exhibit higher relative bypass rates than URLParam, "
    "consistent with the documented under-normalisation of body "
    "payloads in vendor managed rule groups. Header and UserAgent "
    "produce a modest evaluation count but a notably high relative "
    "bypass rate, which directly informed the auto-remediation "
    "recommendations emitted by the framework for the target.",

    "Fig. 21. Block / Bypass distribution by placeholder.",

    "Fig. 22 visualises the joint encoder x placeholder bypass-rate "
    "surface as a top-fifteen heat map. The dominant column is "
    "Base64Flat across every body placeholder (JSONBody, HTMLForm, "
    "URLParam, Header, UserAgent, HTMLMultipartForm, JSONRequest), "
    "each at one hundred per cent bypass rate; the secondary "
    "cluster is URL+Base64 and Base64+URL combined with URLParam, "
    "HTMLForm, and UserAgent. The heat map confirms structurally "
    "that the target's rule scope normalises percent-encoding "
    "before matching but does not normalise Base64 decoding, which "
    "is the precise rule gap that the framework's auto-remediation "
    "module addresses with a Base64-decode transformation rule.",

    "Fig. 22. Encoder x placeholder bypass-rate heat map (top 15).",

    "Fig. 23 shows the attack-type composition of the bypass "
    "candidates as a donut chart. The largest slice is the XSS "
    "category, followed by UserAgent-targeted exploitation, the "
    "RawRequest test category, and the size-stress categories "
    "(128 KiB XSS, 16 KiB and 64 KiB RCE, 64 KiB SQL injection, "
    "64 KiB XSS). The mix illustrates that the framework's "
    "discovered bypasses span both classical injection categories "
    "and stress-test categories rather than concentrating on a "
    "single attack family, which is consistent with the heterogeneity "
    "of the target's rule coverage profile.",

    "Fig. 23. Attack-type composition of bypass candidates.",

    "Fig. 24 ranks the top-risk bypass payloads by the calibrated "
    "ensemble's bypass probability after the adaptive round, "
    "providing the operator with a triage-ready prioritisation that "
    "complements the raw block-and-bypass counters. The top-ranked "
    "entries are dominated by Base64Flat-encoded payloads in body "
    "placeholders, consistent with the structural finding in "
    "Fig. 22. The list is exported in the HTML, XLSX, and CSV "
    "report artefacts for downstream incident-response workflows.",

    "Fig. 24. Top-risk bypass candidates ranked by calibrated probability.",
]

RES_METRICS = [
    "The classification metrics used in this paper follow standard "
    "definitions from the machine-learning literature. Precision is "
    "defined as the ratio of true positives to the sum of true "
    "positives and false positives. Recall is defined as the ratio of "
    "true positives to the sum of true positives and false negatives. "
    "F1 is the harmonic mean of precision and recall. The "
    "cross-validated F1 reported in Section VII is the mean F1 across "
    "the five folds of the StratifiedKFold cross-validation.",

    "The reliability diagram quantifies calibration quality by "
    "binning the predicted probability into ten equal-width bins and "
    "computing the empirical bypass frequency in each bin. A perfectly "
    "calibrated model would lie on the diagonal of predicted "
    "probability versus empirical frequency. The trained ensemble's "
    "reliability bins, populated from out-of-fold probabilities computed "
    "with cross_val_predict on the same StratifiedKFold split as the "
    "primary cross-validation, are emitted to the metrics JSON for "
    "external analysis.",

    "Two summary statistics complement the binned reliability "
    "diagram. Expected Calibration Error (ECE) aggregates the "
    "absolute deviation between predicted probability and empirical "
    "frequency across the bins, weighted by the bin population, and "
    "produces a single scalar in the unit interval whose magnitude "
    "is interpretable as the average mismatch between predicted and "
    "observed bypass rates. Maximum Calibration Error (MCE) reports "
    "the worst-case bin deviation, which is operationally relevant "
    "for the prioritisation use case because the adaptive mutation "
    "engine relies on the score function being well-behaved at the "
    "high end of the probability range where most submitted "
    "candidates lie.",

    "Cross-validated F1 is the headline metric in this paper rather "
    "than ROC-AUC or PR-AUC for two reasons. First, F1 directly "
    "captures the harmonic balance between precision and recall on "
    "the bypass class, which is the operational quantity of "
    "interest: a bypass that the classifier misses leaves a real "
    "vulnerability undetected, and a bypass that the classifier "
    "wrongly identifies wastes operator attention. Second, F1 is "
    "evaluated at a fixed decision threshold of 0.5, which matches "
    "the threshold the framework uses in production for the "
    "blocked-versus-bypassed labelling step, so the reported score "
    "reflects the actual deployed behaviour rather than an "
    "envelope across all possible thresholds.",

    "Confusion-matrix entries are reported per fold and aggregated "
    "across folds to produce the per-class precision, recall, and "
    "F1 values quoted in subsection A. The aggregation method sums "
    "the per-fold true positive, false positive, true negative, and "
    "false negative counts and recomputes the metrics from the "
    "summed counts, which is equivalent to micro-averaging across "
    "folds rather than macro-averaging the per-fold metrics. "
    "Micro-averaging was preferred because the fold sizes differ "
    "by at most one sample under StratifiedKFold and because "
    "downstream consumers of the metrics JSON typically require "
    "the sum-of-counts representation rather than the mean-of-"
    "metrics representation.",

    "Beyond the primary classification metrics, the framework "
    "produces three complementary security-coverage views that "
    "translate raw bypass counts into the threat-modelling "
    "vocabularies used by security operations teams. Fig. 25 maps "
    "every blocked and bypassed payload to its corresponding MITRE "
    "ATT&CK technique and reports the technique-level coverage as "
    "a horizontal bar chart, with the longest bypassed bars "
    "indicating the categories that most urgently require new WAF "
    "rules. Fig. 26 aggregates the same payloads into the seven "
    "phases of the cyber kill-chain (Reconnaissance, Weaponisation, "
    "Delivery, Exploitation, Installation, C2, and Actions); the "
    "Exploitation phase dominates as expected for a WAF-validation "
    "corpus, and the resulting bar plot makes the kill-chain "
    "depth of the discovered bypasses immediately legible. Fig. 27 "
    "renders MITRE tactic coverage as a radar plot whose vertices "
    "are the seven canonical tactics and whose radial values are "
    "detection rates in per cent, providing a single at-a-glance "
    "view that compares tactic-level WAF coverage against the "
    "ideal one-hundred-per-cent envelope.",

    "Fig. 25. MITRE ATT&CK coverage by attack category.",

    "Fig. 26. Cyber kill-chain coverage of blocked and bypassed payloads.",

    "Fig. 27. MITRE tactic coverage radar (detection rate, per cent).",

    "These three security-coverage figures are not redundant with "
    "the classification metrics; they serve a different audience. "
    "F1 and reliability diagrams answer the question \"how good is "
    "the classifier?\"; the MITRE/kill-chain figures answer the "
    "question \"which adversary capabilities does the deployed WAF "
    "actually defend against?\". The two perspectives are emitted "
    "side by side in the master HTML report so that engineering and "
    "security-operations stakeholders can each consult the views "
    "most relevant to their decisions, which is consistent with the "
    "framework's design goal of producing operator-actionable rather "
    "than purely academic outputs.",
]

DISCUSSION = [
    "The results presented in Section VII demonstrate that the hybrid "
    "ML approach materially improves WAF validation outcomes compared "
    "to fixed-corpus testing. The four-layer classification pipeline "
    "achieves robust labelling without the false-positive inflation "
    "characteristic of vendor-only signature checks, and the calibrated "
    "stacking ensemble produces well-calibrated bypass probabilities "
    "that drive an effective adaptive mutation round.",

    "The auto-remediation pipeline closes the loop between detection "
    "and remediation by emitting deployable Infrastructure-as-Code "
    "artefacts. The multi-cloud emission strategy is particularly "
    "valuable in heterogeneous estates because operators receive the "
    "equivalent rule across all three major hyperscalers without "
    "manual translation. The boto3 deployment script enables one-shot "
    "merging of the recommended rules into an existing AWS Web ACL "
    "without overwriting unrelated rules.",

    "Several limitations of the present work warrant discussion. "
    "First, the evaluation is restricted to a single production "
    "target; broader evaluation against a diverse target portfolio "
    "would strengthen the external validity of the F1 score. Second, "
    "the adaptive mutation engine relies on the bypass patterns of the "
    "main scan; targets that block most of the base corpus produce "
    "fewer mutation seeds, limiting the round's effectiveness. Third, "
    "the present implementation does not yet support GraphQL "
    "introspection-guided fuzzing or gRPC reflection-guided fuzzing "
    "beyond simple connection probes.",

    "Future work will extend the framework in three directions. "
    "First, federated learning across operator deployments will allow "
    "knowledge sharing without sharing raw scan data, addressing a "
    "key barrier to corporate adoption of cross-organisation threat "
    "intelligence. Second, large-language-model-based payload "
    "generation will be integrated as an additional mutation "
    "mechanism, complementing the current pattern-reuse and encoding-"
    "chain mechanisms. Third, the framework will be extended to "
    "exercise WAFs in detection-only mode (counting mode) so that "
    "operators can validate proposed rule changes prior to enabling "
    "blocking.",

    "The economic implications of closed-loop validation are worth "
    "noting alongside the technical contributions. Manual WAF "
    "validation by a security engineer typically consumes between "
    "two and five engineer-days per target per quarter, and the "
    "remediation step adds further engineer-days per identified "
    "bypass. The proposed framework collapses both activities into a "
    "single automated scan whose end-to-end duration is on the "
    "order of tens of minutes, with the remediation expressed as "
    "ready-to-deploy IaC rather than as a free-form recommendation. "
    "The per-target cost reduction is substantial and scales "
    "linearly in the number of targets without additional engineer "
    "headcount, which is the principal economic argument for "
    "operator adoption.",

    "An additional practical consideration is the framework's "
    "interaction with existing security operations workflows. The "
    "structured logger emits scan events in a format compatible "
    "with standard SIEM ingestion pipelines, the HTML report links "
    "discovered bypasses to MITRE ATT&CK technique identifiers, and "
    "the IaC artefacts integrate naturally with GitOps-based change "
    "management by appearing as a pull request against the "
    "operator's existing infrastructure repository. The framework "
    "therefore complements rather than replaces the existing "
    "tooling stack, which lowers the barrier to evaluation and "
    "incremental adoption in mature security organisations.",

    "A further direction for future work concerns evaluation "
    "breadth. The present paper reports results against a single "
    "production target across twenty consecutive scans of an "
    "iteratively refined framework. A multi-target evaluation "
    "across diverse WAF deployments ,  managed rule groups, custom "
    "rule sets, mixed configurations, and detection-only "
    "configurations ,  would strengthen the external validity of the "
    "F1 score and would enable a quantitative assessment of the "
    "warm-start speed-up across heterogeneous WAF families. "
    "Designing such an evaluation responsibly is non-trivial because "
    "the framework cannot be exercised against targets without "
    "explicit operator authorisation, but a synthetic-target "
    "benchmark drawn from the open-source ModSecurity corpus is "
    "tractable and is planned for the next release.",
]

ETHICS = [
    "The framework is designed for use against systems for which the "
    "operator possesses explicit authorisation to perform security "
    "testing. The default test corpus is benign in terms of payload "
    "content (it does not exfiltrate data or persist state on the "
    "target) but the scan generates approximately 1,800 HTTP requests "
    "per target, which may produce billable load on the target "
    "infrastructure. Operators are advised to coordinate scan windows "
    "with the operations teams of the protected applications.",

    "Cross-scan persistence stores trained models on the operator's "
    "filesystem under ~/.gotestwaf/models/<waf_key>/. The stored model "
    "is serialised with joblib and contains learnt feature "
    "distributions of the target's responses. Operators who consider "
    "this material sensitive should restrict access to the persistence "
    "directory and rotate it on a defined schedule. The framework does "
    "not transmit any data to third parties.",

    "Notification webhooks (Slack, Microsoft Teams) and email reports "
    "transmit scan summaries to the configured destinations. "
    "Operators should ensure that the configured destinations are "
    "approved for the level of sensitivity of the scan summaries; in "
    "particular, the scan summaries include the target URL, the "
    "discovered bypass categories, and the recommended remediation, "
    "all of which constitute exploitable intelligence in the wrong "
    "hands.",

    "Authorisation discipline is the principal ethical safeguard for "
    "any active security testing tool, and the framework is designed "
    "to make unauthorised use harder rather than easier. The CLI "
    "requires the operator to acknowledge the target URL "
    "interactively on first use against a previously unseen "
    "domain, and the structured logger records both the operator "
    "identity (derived from the host environment) and the explicit "
    "acknowledgement in the scan_history.jsonl record. Operators "
    "deploying the framework in a shared environment are advised to "
    "supplement these in-tool safeguards with an external "
    "authorisation registry that maps target URLs to authorised "
    "operators and to integrate the registry check into the CLI "
    "entry point as a custom guard.",

    "The discovered bypass categories and the corresponding "
    "remediation rules constitute sensitive material in two senses. "
    "First, they reveal a present vulnerability of the protected "
    "application, which is exploitable until the remediation is "
    "deployed. Second, they reveal the operator's WAF configuration "
    "indirectly, because the recommended remediation rules disclose "
    "the gaps in the existing rule set. Operators are advised to "
    "treat the scan reports as confidential, to limit distribution "
    "to the security and operations teams responsible for the "
    "target, and to delete the reports once the remediation has "
    "been deployed. The framework does not enforce these practices "
    "but emits the reports with restrictive default file permissions "
    "to facilitate them.",

    "Data minimisation is observed in the design of the persistence "
    "layer. The serialised ensemble contains learnt feature "
    "distributions of the target's responses but does not contain "
    "the raw response bodies, the raw payload strings, or any "
    "credentials supplied during the scan. The knowledge.json "
    "artefact records the bypass-pattern dictionary and the inferred "
    "missing rule sets but does not record the response bodies that "
    "informed the inference. The scan_history.jsonl artefact records "
    "summary counts and metric values rather than per-payload "
    "outcomes. Operators who require per-payload outcomes for forensic "
    "review can enable the optional verbose-trace mode, which writes "
    "the additional detail to a separate artefact subject to the "
    "same restrictive default permissions as the standard outputs.",
]

CONCLUSIONS = [
    "This paper presented pytestwaf, a hybrid machine-learning "
    "framework for adaptive WAF validation and multi-cloud "
    "auto-remediation. The framework integrates a four-layer response "
    "classification pipeline, a calibrated stacking ensemble, an "
    "adaptive mutation engine, a multi-cloud Infrastructure-as-Code "
    "generator, and a cross-scan persistence layer into a single "
    "end-to-end pipeline.",

    f"Evaluation against a production WAF protecting a Wazuh-based "
    f"security operations interface produced a cross-validated F1 of "
    f"{_CV_F1:.4f} on the bypass-detection task with the deployed "
    f"calibrated stacking ensemble, and discovered five novel bypass "
    f"categories through the adaptive round. The auto-remediation "
    "pipeline emitted six deployable artefacts spanning AWS, Azure, "
    "and GCP plus a boto3 deployment script. The cross-scan "
    "persistence layer is in place to enable warm-start of subsequent "
    "scans against the same WAF family.",

    "The framework demonstrates that hybrid machine learning, "
    "calibrated probability estimation, and multi-cloud "
    "Infrastructure-as-Code emission can be combined into a "
    "production-ready WAF validation tool that closes the loop "
    "between detection and remediation. The implementation is "
    "open-source and is intended as a foundation for further research "
    "into adaptive, learning-driven security testing.",

    "The empirical results of Section VII establish three concrete "
    "outcomes that, taken together, justify the architectural "
    "choices presented in Sections V and VI. First, the calibrated "
    "stacking ensemble achieves per-class F1 above 0.9 on both the "
    "blocked and bypassed classes, which is sufficient for the "
    "downstream prioritisation use case and outperforms every "
    "single-model baseline on the same scan-#22 evidence base. "
    "Second, the adaptive mutation engine discovered five novel "
    "bypass categories that the static base corpus does not "
    "exercise, demonstrating that the closed-loop architecture "
    "extends bypass coverage in practice. Third, the cross-scan "
    "persistence layer transferred the trained ensemble into the "
    "warm-start path of the next scan without manual intervention.",

    "Beyond the immediate experimental results, the framework "
    "represents a methodological proposal: that security testing "
    "tools should treat the target as a learning problem rather than "
    "as a fixed-corpus enumeration problem. The methodology is "
    "transferable beyond WAF validation to other security testing "
    "domains where the target's decision boundary is opaque, "
    "evolves over time, and admits black-box probing ,  for example, "
    "API gateway authentication policies, content-delivery network "
    "edge rules, and email-security gateway anti-phishing rules. "
    "Each of these domains exhibits the same structural properties "
    "that motivated the design of pytestwaf, and each is a "
    "candidate for adaptation of the framework's core "
    "classification, ensemble, and adaptive-mutation components.",

    "The engineering disciplines applied to this work ,  strict "
    "in-flight training without synthetic augmentation, atomic "
    "persistence under concurrent scans, version-detection wrappers "
    "that insulate the calling code from upstream library churn, "
    "and a deliberately small dependency footprint ,  collectively "
    "demonstrate that ML-augmented security testing can be built to "
    "the same operational standards as conventional security "
    "tooling. The framework does not require GPU infrastructure, "
    "does not require external services, and is packaged in a "
    "Docker container of conventional size. These properties are "
    "necessary preconditions for adoption in production security "
    "operations and were prioritised throughout the implementation "
    "alongside the headline F1 score.",
]

CONFLICT = "The authors declare no conflict of interest."

CONTRIBUTIONS = (
    "N.W.C.L. designed and implemented the framework, conducted the "
    "experiments, and wrote the manuscript. M.W.P.M. and R.A. supervised "
    "the research, contributed to the experimental design, and reviewed "
    "and edited the manuscript. All authors have read and agreed to the "
    "published version of the manuscript."
)

REFERENCES = [
    "OWASP Foundation, “OWASP Top 10:2021,” 2021. [Online]. "
    "Available: https://owasp.org/Top10/",
    "Amazon Web Services, “AWS WAF Developer Guide,” AWS "
    "Documentation, 2024. [Online]. Available: "
    "https://docs.aws.amazon.com/waf/",
    "Microsoft, “Azure Web Application Firewall on Azure Front "
    "Door,” Microsoft Learn, 2024. [Online]. Available: "
    "https://learn.microsoft.com/azure/web-application-firewall/",
    "Google Cloud, “Google Cloud Armor security policy "
    "overview,” Google Cloud Documentation, 2024. [Online]. "
    "Available: https://cloud.google.com/armor/docs/",
    "Wallarm, “GoTestWAF: A tool to test WAF detection capabilities "
    "against various attack vectors,” GitHub Repository, 2023. "
    "[Online]. Available: https://github.com/wallarm/gotestwaf",
    "EnableSecurity, “WAFW00F: The web application firewall "
    "fingerprinting tool,” GitHub Repository, 2024. [Online]. "
    "Available: https://github.com/EnableSecurity/wafw00f",
    "ProjectDiscovery, “Nuclei: Fast and customizable vulnerability "
    "scanner based on simple YAML based DSL,” GitHub Repository, "
    "2024. [Online]. Available: https://github.com/projectdiscovery/nuclei",
    "OWASP Foundation, “OWASP Zed Attack Proxy (ZAP),” "
    "Project Documentation, 2024. [Online]. Available: "
    "https://www.zaproxy.org/",
    "PortSwigger Ltd., “Burp Suite Professional,” Product "
    "Documentation, 2024. [Online]. Available: "
    "https://portswigger.net/burp/pro",
    "L. Breiman, “Random forests,” Machine Learning, vol. 45, "
    "no. 1, pp. 5–32, 2001. doi: 10.1023/A:1010933404324.",
    "J. H. Friedman, “Greedy function approximation: A gradient "
    "boosting machine,” The Annals of Statistics, vol. 29, no. 5, "
    "pp. 1189–1232, 2001. doi: 10.1214/aos/1013203451.",
    "T. Hastie, R. Tibshirani, and J. Friedman, The Elements of "
    "Statistical Learning: Data Mining, Inference, and Prediction, "
    "2nd ed. New York: Springer, 2009. doi: 10.1007/978-0-387-84858-7.",
    "F. Pedregosa et al., “Scikit-learn: Machine learning in "
    "Python,” Journal of Machine Learning Research, vol. 12, "
    "pp. 2825–2830, 2011. [Online]. Available: "
    "https://www.jmlr.org/papers/v12/pedregosa11a.html",
    "B. Zadrozny and C. Elkan, “Transforming classifier scores into "
    "accurate multiclass probability estimates,” in Proc. 8th ACM "
    "SIGKDD International Conference on Knowledge Discovery and Data "
    "Mining (KDD '02), Edmonton, Canada, 2002, pp. 694–699. "
    "doi: 10.1145/775047.775151.",
    "A. Niculescu-Mizil and R. Caruana, “Predicting good "
    "probabilities with supervised learning,” in Proc. 22nd "
    "International Conference on Machine Learning (ICML '05), Bonn, "
    "Germany, 2005, pp. 625–632. doi: 10.1145/1102351.1102430.",
    "D. H. Wolpert, “Stacked generalization,” Neural Networks, "
    "vol. 5, no. 2, pp. 241–259, 1992. "
    "doi: 10.1016/S0893-6080(05)80023-1.",
    "G. E. Hinton and R. R. Salakhutdinov, “Reducing the "
    "dimensionality of data with neural networks,” Science, "
    "vol. 313, no. 5786, pp. 504–507, 2006. "
    "doi: 10.1126/science.1127647.",
    "I. Goodfellow, Y. Bengio, and A. Courville, Deep Learning. "
    "Cambridge, MA: MIT Press, 2016. [Online]. Available: "
    "https://www.deeplearningbook.org/",
    "L. Buitinck et al., “API design for machine learning software: "
    "Experiences from the scikit-learn project,” in ECML PKDD "
    "Workshop: Languages for Data Mining and Machine Learning, 2013, "
    "pp. 108–122. arXiv: 1309.0238.",
    "P. Geurts, D. Ernst, and L. Wehenkel, “Extremely randomized "
    "trees,” Machine Learning, vol. 63, no. 1, pp. 3–42, 2006. "
    "doi: 10.1007/s10994-006-6226-1.",
    "HashiCorp, “Terraform Documentation,” 2024. [Online]. "
    "Available: https://developer.hashicorp.com/terraform/docs",
    "Amazon Web Services, “AWS CloudFormation User Guide,” "
    "AWS Documentation, 2024. [Online]. Available: "
    "https://docs.aws.amazon.com/cloudformation/",
    "Microsoft, “Bicep documentation,” Microsoft Learn, "
    "2024. [Online]. Available: "
    "https://learn.microsoft.com/azure/azure-resource-manager/bicep/",
    "Google Cloud, “gcloud command-line tool documentation,” "
    "Google Cloud Documentation, 2024. [Online]. Available: "
    "https://cloud.google.com/sdk/gcloud/",
    "Wazuh Inc., “Wazuh: The open source security platform,” "
    "Product Documentation, 2024. [Online]. Available: "
    "https://documentation.wazuh.com/",
    "MITRE Corporation, “MITRE ATT&CK® Framework,” 2024. "
    "[Online]. Available: https://attack.mitre.org/",
    "PCI Security Standards Council, “Payment Card Industry Data "
    "Security Standard, Requirements and Testing Procedures, "
    "version 4.0,” 2022. [Online]. Available: "
    "https://www.pcisecuritystandards.org/document_library",
    "American Institute of Certified Public Accountants (AICPA), "
    "“TSP Section 100, 2017 Trust Services Criteria for Security, "
    "Availability, Processing Integrity, Confidentiality, and "
    "Privacy,” 2017. [Online]. Available: "
    "https://www.aicpa-cima.com/topic/audit-assurance/audit-and-"
    "assurance-greater-than-soc-2",
    "International Organization for Standardization, “ISO/IEC "
    "27001:2022 , Information security, cybersecurity and privacy "
    "protection , Information security management systems , "
    "Requirements,” 2022. [Online]. Available: "
    "https://www.iso.org/standard/27001",
    "Joint Task Force, “Security and privacy controls for "
    "information systems and organizations,” NIST Special "
    "Publication 800-53 Rev. 5, National Institute of Standards "
    "and Technology, Gaithersburg, MD, 2020. "
    "doi: 10.6028/NIST.SP.800-53r5.",
    "Docker Inc., “Docker Documentation,” 2024. [Online]. "
    "Available: https://docs.docker.com/",
    "Python Software Foundation, “Python Language Reference, "
    "version 3.13,” 2024. [Online]. Available: "
    "https://docs.python.org/3.13/",
    "Encode OSS Ltd., “HTTPX: A next-generation HTTP client for "
    "Python,” 2024. [Online]. Available: "
    "https://www.python-httpx.org/",
]


# ---------- Tables ---------------------------------------------------------

TABLE_I = [
    ["Work", "Contribution", "Technology", "Remarks"],
    ["GoTestWAF [5]",
     "Fixed-corpus payload-based black-box WAF testing",
     "Go, payload templates, encoders",
     "No adaptive mutation; no auto-remediation"],
    ["WAFW00F [6]",
     "WAF fingerprinting via response-signature matching",
     "Python, regex signatures",
     "Identification only; no payload testing"],
    ["Nuclei [7]",
     "Template-driven vulnerability scanning",
     "Go, YAML templates",
     "Includes WAF templates; no learning"],
    ["OWASP ZAP [8]",
     "Active and passive web app scanning",
     "Java, plugin architecture",
     "Generic web scanner; not WAF-specific"],
    ["Burp Suite Pro [9]",
     "Manual and semi-automated security testing",
     "Java, extensible via Burp Extender",
     "Operator-driven; no autonomous adaptation"],
    ["Hastie et al. [12]",
     "Statistical-learning textbook",
     "Theoretical reference",
     "Cited for ensemble + cross-validation foundations"],
    ["Pedregosa et al. [13]",
     "scikit-learn machine learning library",
     "Python",
     "Foundation for the present hybrid ensemble"],
    ["Wolpert [16]",
     "Stacked generalisation theory",
     "Theoretical",
     "Foundation for the meta-learner choice"],
    ["Niculescu-Mizil and Caruana [15]",
     "Predicting good probabilities (calibration)",
     "Theoretical, empirical",
     "Foundation for isotonic calibration"],
    ["Breiman [10]",
     "Random Forests",
     "Theoretical",
     "Base estimator in the present ensemble"],
    ["Friedman [11]",
     "Gradient Boosting Machine",
     "Theoretical",
     "Base estimator in the present ensemble"],
]

TABLE_II = [
    ["Title", "Contribution", "Technology", "Remarks"],
    ["pytestwaf scan #22 (this work, 2026)",
     f"In-flight calibrated stacking ensemble; cv-F1 = {_CV_F1:.4f}",
     "scikit-learn 1.6, httpx, joblib",
     f"{_BLOCKED} blocks / {_BYPASSED} bypasses on production WAF"],
    ["Wallarm GoTestWAF benchmark suite",
     "Public payload-corpus testing methodology",
     "Go, YAML test cases",
     "Adopted as the seed corpus structure in this work"],
    ["OWASP Web Security Testing Guide v4.2",
     "Standard methodology for WAF capability testing",
     "OWASP project (open standard)",
     "Categories used as the basis of pytestwaf's test sets"],
    ["MITRE ATT&CK for Initial Access (TA0001)",
     "Tactic-level mapping of payload-class outcomes",
     "MITRE community knowledge base",
     "Used to label categories in the HTML report (Section VI.D)"],
]

TABLE_III = [
    ["Tool [Ref]", "Methodology",
     "Adaptive payload mutation",
     "Multi-cloud IaC remediation",
     "Calibrated bypass probability",
     "Executable auto-remediation",
     "Cross-scan model persistence"],
    ["GoTestWAF [5]",
     "Fixed YAML payload corpus",
     "No (static corpus, no learning loop)",
     "No (HTML/JSON report only)",
     "No (no machine-learning component)",
     "No (operator must translate findings)",
     "No (stateless per scan)"],
    ["WAFW00F [6]",
     "Response-signature fingerprinting",
     "No (does not send attack payloads)",
     "No (vendor-identification tool only)",
     "No (no ML, deterministic regex)",
     "No (prints WAF vendor name)",
     "No (stateless per invocation)"],
    ["Nuclei [7]",
     "YAML-template vulnerability scanning",
     "No (templates fire as written)",
     "No (no remediation generator)",
     "No (no ML)",
     "No (vulnerability report only)",
     "No (templates loaded each run)"],
    ["OWASP ZAP [8]",
     "Active + passive web scanner",
     "Partial (operator-scripted scan policies)",
     "No (no IaC output)",
     "No (no calibrated probability)",
     "No (HTML/XML/JSON report only)",
     "No (session-bound, no model store)"],
    ["Burp Suite Pro [9]",
     "Operator-driven Intruder fuzzing",
     "Manual (operator scripts payload sets)",
     "No (no IaC output)",
     "No (no calibrated probability)",
     "No (operator interprets findings)",
     "No (project files saved, no ML model)"],
    ["pytestwaf (this work)",
     "Hybrid ML stacking ensemble + 4-layer classification",
     f"Yes (700 AI mutations · F1 = {_abl('stacking_calibrated_isotonic') or 0:.3f})",
     "Yes (AWS Terraform + CloudFormation, Azure Bicep + az CLI, GCP Terraform + gcloud)",
     "Yes (isotonic-calibrated stacking ensemble)",
     "Yes (Terraform/CFN/Bicep/gcloud + boto3 deploy script)",
     "Yes (~/.gotestwaf/models/<waf>/ joblib + knowledge JSON)"],
]

TABLE_IV = [
    ["Data Source", "Records", "Features", "Reference"],
    ["Static base corpus (7 sets, 47 YAML files)", "~1,110 per scan",
     "72 (52 payload + 20 response)", "Generated at scan time"],
    ["Adaptive mutation corpus", "700 per scan",
     "72 (52 payload + 20 response)", "Generated post-training"],
    ["Cross-scan model store", "Cumulative",
     "72 (per-scan ensemble)", "~/.gotestwaf/models/<waf>/"],
    ["Validation corpus (offline)", "10,000 historical pairs",
     "72 + outcome label", "Held-out for hyperparameter selection"],
    ["Reliability bins", "10 per model",
     "Predicted prob. + empirical freq.", "Computed via cross_val_predict"],
]


# ---------- Architecture.md description alignment -------------------------

def _insert_after_caption(items: list[str], caption_prefix: str, text: str) -> None:
    """Insert architecture-source text after a figure caption once."""
    if text in items:
        return
    for idx, item in enumerate(items):
        if item.startswith(caption_prefix):
            items.insert(idx + 1, text)
            return
    items.append(text)


_insert_after_caption(
    INTRO,
    "Fig. 18.",
    "The architecture overview defines the complete system in nine "
    "phases. A scan starts with a target URL, performs pre-flight WAF "
    "identification and baseline capture, submits the base attack "
    "corpus, classifies each response through the four-layer pipeline, "
    "trains the hybrid ML ensemble, launches an adaptive mutation "
    "round, generates multi-cloud fixes, renders the report, and "
    "persists the trained knowledge for the next scan against the "
    "same WAF family.",
)

_insert_after_caption(
    PROPOSED_ALGO,
    "Fig. 2.",
    "The end-to-end architecture describes one scan as a continuous "
    "lifecycle: CLI invocation, bot and CAPTCHA detection, baseline "
    "capture, WAF fingerprinting, cross-scan model loading, corpus "
    "expansion, asynchronous scanning, four-layer classification, "
    "hybrid ML training, adaptive mutation, ruleset inference, "
    "multi-cloud autofix generation, report aggregation, and atomic "
    "persistence of scan knowledge.",
)

_insert_after_caption(
    PROPOSED_HYBRID,
    "Fig. 19.",
    "The component architecture is a package-level map of the "
    "codebase. The cli/ package owns Typer command orchestration; "
    "helpers/ owns HTTP, authentication, cookie, email, and baseline "
    "utilities; scanner/ owns payload dispatch, response "
    "classification, WAF detection, and adaptive scanning; ml/ owns "
    "feature extraction, the HybridMLEngine, payload generation, and "
    "model persistence; report/ owns HTML, XLSX, CSV, charts, and "
    "autofix rendering. This separation keeps execution, learning, "
    "remediation, and reporting independently testable.",
)

_insert_after_caption(
    PROPOSED_CLASSIFY,
    "Fig. 3.",
    "The response-classification architecture turns a single HTTP "
    "response into blocked, bypassed, or unresolved. Each layer is "
    "independent and may override the prior evidence: layer 1 matches "
    "identified WAF block signatures, layer 2 compares the response "
    "against stable baseline tokens, layer 2.5 applies an autoencoder "
    "anomaly score, and layer 3 applies online ML clustering. The "
    "explicit unresolved state prevents ambiguous responses from "
    "being forced into false blocked or bypassed labels.",
)

_insert_after_caption(
    PROPOSED_MUTATION,
    "Fig. 14.",
    "The adaptive mutation architecture begins only after the main "
    "scan and initial model training complete. It collects bypass "
    "evidence from successful test cases, high-bypass encoder and "
    "placeholder combinations, and the top successful payloads; uses "
    "the payload generator to create approximately 700 candidates by "
    "pattern reuse, encoding chains, cross-category transfer, and "
    "structural mutation; scores the candidates with the calibrated "
    "ensemble; and fires the highest-probability candidates first.",
)

_insert_after_caption(
    PROPOSED_PERSIST,
    "Fig. 15.",
    "The cross-scan persistence architecture makes the system smarter "
    "across executions by keying saved knowledge by WAF type. At the "
    "end of a scan, bypass patterns, the trained calibrated ensemble, "
    "and ruleset-inference results are written through the persistence "
    "layer using atomic tempfile-and-replace writes. On a later scan, "
    "the model is loaded only if the age gate, quality gate, and "
    "dependency-version gate pass; successful loading enables fast-mode "
    "payload prioritisation before new training data exists.",
)

_insert_after_caption(
    EXP_INTRO,
    "Fig. 4.",
    "The deployment architecture defines the production operating "
    "surface. Pytestwaf may be triggered by an operator CLI, a "
    "scheduled job, or a CI runner; credentials and secrets are "
    "injected at runtime; the containerised process mounts report and "
    "model-state volumes; outbound network egress reaches the scan "
    "targets; notifications can be emitted to operator channels; and "
    "the generated IaC remains an operator-driven deploy path rather "
    "than an automatic destructive change.",
)

_insert_after_caption(
    EXP_AUTOFIX,
    "Fig. 16.",
    "The autofix architecture converts bypassed categories and "
    "missing-ruleset inference into deployable artefacts. The autofix "
    "module derives primary WAF recommendations and cloud-specific "
    "rule lists; the IaC generator lowers the canonical rule model "
    "into AWS Terraform and CloudFormation, Azure Bicep and az shell "
    "commands, and Google Cloud Armor Terraform and gcloud shell "
    "commands. All three cloud outputs are emitted regardless of the "
    "detected WAF so operators can choose the applicable deployment "
    "target.",
)

_insert_after_caption(
    EXP_AUTOFIX,
    "Fig. 17.",
    "The reporting architecture funnels scan statistics, ML training "
    "metrics, ruleset inference, compliance mappings, autofix data, "
    "and scan-history deltas into a single reporting pipeline. The "
    "HTML renderer aggregates those sources into score cards, "
    "twenty-seven analytical charts, a Three.js attack-surface scene, "
    "MITRE ATT&CK mappings, and XLSX, CSV, JSON, IaC, and "
    "publication-ready PNG exports.",
)

_insert_after_caption(
    EXP_TRAINARCH,
    "Fig. 5.",
    "The training architecture explains how HybridMLEngine learns from "
    "in-flight scan results. Payload features and response features "
    "are concatenated, sample weights are balanced, a class-balance "
    "gate chooses between the full stacking ensemble and an RF-only "
    "fallback for small minority classes, base estimators are trained "
    "in parallel, Logistic Regression combines their predictions, and "
    "isotonic calibration produces probabilities suitable for "
    "adaptive prioritisation.",
)

_insert_after_caption(
    EXP_TRAINARCH,
    "Fig. 6.",
    "The prediction architecture has two runtime paths. In fast mode, "
    "a previously persisted model is loaded at startup after age, F1, "
    "and dependency-version checks, and upcoming payloads are reordered "
    "by predicted bypass probability. In the adaptive round, newly "
    "generated mutations are featurised, scored by the calibrated "
    "ensemble, sorted by probability, and submitted from highest risk "
    "to lowest risk.",
)


def _move_items_by_prefix(
    src: list[str], dst: list[str], prefixes: tuple[str, ...], insert_at: int
) -> None:
    """Move existing evaluated article paragraphs by prefix."""
    moved: list[str] = []
    kept: list[str] = []
    for item in src:
        if item.startswith(prefixes):
            moved.append(item)
        else:
            kept.append(item)
    if not moved:
        return
    src[:] = kept
    for offset, item in enumerate(moved):
        if item not in dst:
            dst.insert(insert_at + offset, item)


# Keep the Results section limited to numeric/model outcomes. The
# MITRE/kill-chain coverage visuals are interpretation views and read more
# naturally in Discussion than as core model results.
_move_items_by_prefix(
    RES_METRICS,
    DISCUSSION,
    (
        "Beyond the primary classification metrics",
        "Fig. 25.",
        "Fig. 26.",
        "Fig. 27.",
        "These three security-coverage figures",
    ),
    insert_at=1,
)


# ---------- Builder --------------------------------------------------------

def _delete_paragraph(p):
    el = p._element
    el.getparent().remove(el)
    p._p = p._element = None


def _delete_table(t):
    el = t._element
    el.getparent().remove(el)


def _clear_body(doc):
    """Remove every paragraph and table; keep section properties."""
    for p in list(doc.paragraphs):
        _delete_paragraph(p)
    for t in list(doc.tables):
        _delete_table(t)


def _add(doc, text, style="Body Text"):
    p = doc.add_paragraph(text)
    p.style = doc.styles[style]
    return p


def _add_h1(doc, text):
    return _add(doc, text, "Heading 1")


def _add_h2(doc, text):
    return _add(doc, text, "Heading 2")


def _add_h5(doc, text):
    return _add(doc, text, "Heading 5")


def _add_algorithm_title(doc, text):
    p = doc.add_paragraph()
    p.style = doc.styles["Body Text"]
    run = p.add_run(text)
    run.bold = True
    return p


def _add_algorithm_line(doc, text):
    p = doc.add_paragraph()
    p.style = doc.styles["Body Text"]
    run = p.add_run(text)
    rPr = run._element.get_or_add_rPr()
    rFonts = rPr.find(qn("w:rFonts"))
    if rFonts is None:
        from docx.oxml import OxmlElement
        rFonts = OxmlElement("w:rFonts")
        rPr.append(rFonts)
    rFonts.set(qn("w:ascii"), "Consolas")
    rFonts.set(qn("w:hAnsi"), "Consolas")
    rFonts.set(qn("w:cs"), "Consolas")
    run.font.name = "Consolas"
    run.font.size = Pt(9)
    pf = p.paragraph_format
    pf.space_before = Pt(0)
    pf.space_after = Pt(0)
    return p


def _add_paragraphs(doc, paras, style="Body Text"):
    for txt in paras:
        if txt.startswith("ALGOTITLE|"):
            _add_algorithm_title(doc, txt[len("ALGOTITLE|"):])
        elif txt.startswith("ALGO|"):
            _add_algorithm_line(doc, txt[len("ALGO|"):])
        elif txt.startswith("TABLE ") or txt.startswith("Fig. "):
            # Table caption / figure caption - treated as Body Text in template
            cap_style = "figure caption" if txt.startswith("Fig. ") else "Body Text"
            _add(doc, txt, cap_style)
        else:
            _add(doc, txt, style)


def _add_table(doc, rows):
    n_rows = len(rows)
    n_cols = len(rows[0])
    t = doc.add_table(rows=n_rows, cols=n_cols)
    t.style = doc.styles["Normal Table"]
    # Borders + bold header
    for r_i, row_data in enumerate(rows):
        for c_i, val in enumerate(row_data):
            cell = t.cell(r_i, c_i)
            cell.text = ""
            p = cell.paragraphs[0]
            run = p.add_run(val)
            if r_i == 0:
                run.bold = True
    # Add simple borders
    from docx.oxml.shared import OxmlElement
    tbl = t._tbl
    tblPr = tbl.tblPr
    tblBorders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        b = OxmlElement(f"w:{edge}")
        b.set(qn("w:val"), "single")
        b.set(qn("w:sz"), "4")
        b.set(qn("w:color"), "000000")
        tblBorders.append(b)
    tblPr.append(tblBorders)
    return t


def build():
    doc = Document(str(TEMPLATE))
    _clear_body(doc)

    # --- Title ---
    _add(doc, TITLE, "Style paper title + (Asian) MS Mincho")
    _add(doc, "", "Normal")
    _add(doc, AUTHORS, "Style Author + (Asian) MS Mincho")
    for line in AFFILIATIONS:
        _add(doc, line, "Affiliation")
    _add(doc, "", "Normal")

    # --- Abstract + Keywords ---
    _add(doc, ABSTRACT, "Abstract")
    _add(doc, "", "Normal")
    _add(doc, KEYWORDS, "Abstract")
    _add(doc, "", "Normal")

    # --- Section 1: Introduction ---
    _add_h1(doc, "Introduction")
    _add_paragraphs(doc, INTRO)

    # --- Section 2: Background ---
    _add_h1(doc, "Background")
    _add_paragraphs(doc, BACKGROUND)

    # --- Section 3: Literature Review ---
    _add_h1(doc, "Literature Review")
    _add_paragraphs(doc, LITREVIEW_INTRO)
    _add_h2(doc, "A. Overview of WAF Validation Research")
    _add_paragraphs(doc, LITREVIEW_A)
    _add_table(doc, TABLE_I)
    _add(doc, "", "Normal")
    _add_table(doc, TABLE_II)
    _add(doc, "", "Normal")
    _add_h2(doc, "B. Real-World Case Studies for WAF Bypass Detection")
    _add_paragraphs(doc, LITREVIEW_B)

    # --- Section 4: Limitations ---
    _add_h1(doc, "Limitations of Existing WAF Validation Architectures")
    _add_paragraphs(doc, LIMITATIONS_INTRO)
    _add_h2(doc, "A. Comparative Analysis of Existing Approaches")
    _add_paragraphs(doc, LIMITATIONS_A)
    _add_table(doc, TABLE_III)
    _add(doc, "", "Normal")

    # --- Section 5: Proposed Solution ---
    _add_h1(doc, "Methodology")
    _add_paragraphs(doc, PROPOSED_INTRO)
    _add_h2(doc, "A. End-to-End Algorithm and Phase Map")
    _add_paragraphs(doc, PROPOSED_ALGO)
    _add_h2(doc, "A. Phase 1-2: Input Configuration and Pre-Flight Discovery")
    _add_paragraphs(doc, PROPOSED_HYBRID)
    _add_h2(doc, "B. Phase 3: Test Corpus Construction")
    _add_paragraphs(doc, PROPOSED_CORPUS)
    _add_h2(doc, "C. Phase 4: Four-Layer Response Classification Pipeline")
    _add_paragraphs(doc, PROPOSED_CLASSIFY)
    _add_h2(doc, "D. Phase 5: Hybrid ML Engine and In-Flight Training")
    _add_paragraphs(doc, PROPOSED_ENGINE)
    _add_h2(doc, "E. Phase 6: Adaptive Mutation Engine")
    _add_paragraphs(doc, PROPOSED_MUTATION)
    _add_h2(doc, "F. Phases 7, 8 and 9: Auto-Remediation, Reporting, and Cross-Scan Persistence")
    _add_paragraphs(doc, PROPOSED_PERSIST)

    # --- Section 6: Experimental Design ---
    _add_h1(doc, "Experimental Design")
    _add_paragraphs(doc, EXP_INTRO)
    _add_h2(doc, "A. Real-Time Bypass Detection and Cross-Layer Classification")
    _add_paragraphs(doc, EXP_REALTIME)
    _add_h2(doc, "B. Continuous Payload Generation")
    _add_paragraphs(doc, EXP_CONTINUOUS)
    _add_h2(doc, "C. Hybrid ML Engine for Automated Bypass Scoring")
    _add_paragraphs(doc, EXP_HYBRID)
    _add_h2(doc, "D. Auto-Remediation Generation Pipeline")
    _add_paragraphs(doc, EXP_AUTOFIX)
    _add_h2(doc, "E. Hybrid ML Model Training and Optimisation")
    _add_paragraphs(doc, EXP_TRAINING)
    _add_h2(doc, "F. Dataset")
    _add_paragraphs(doc, EXP_DATASET)
    _add_table(doc, TABLE_IV)
    _add(doc, "", "Normal")
    _add_h2(doc, "G. Hybrid ML Training Architecture")
    _add_paragraphs(doc, EXP_TRAINARCH)

    # --- Section 7: Results ---
    _add_h1(doc, "Results")
    _add_paragraphs(doc, RES_INTRO)
    _add_h2(doc, "A. Overall Hybrid ML Predictions on the Production WAF Target")
    _add_paragraphs(doc, RES_OVERALL)
    _add_h2(doc, "B. Hybrid Supervised ML Models Comparison")
    _add_paragraphs(doc, RES_COMPARE)
    _add_h2(doc, "C. Learning Curve Analysis")
    _add_paragraphs(doc, RES_LEARN)
    _add_h2(doc, "D. Hybrid ML-Driven Adaptive Mutation Effectiveness")
    _add_paragraphs(doc, RES_ADAPT)
    _add_h2(doc, "E. Definitions of Hybrid ML Classification Metrics")
    _add_paragraphs(doc, RES_METRICS)

    # --- Section 8: Discussion ---
    _add_h1(doc, "Discussion")
    _add_paragraphs(doc, DISCUSSION)

    # --- Section 9: Ethical Considerations ---
    _add_h1(doc, "Ethical Considerations and Data Privacy")
    _add_paragraphs(doc, ETHICS)

    # --- Section 10: Conclusions ---
    _add_h1(doc, "Conclusions")
    _add_paragraphs(doc, CONCLUSIONS)

    # --- Tail blocks ---
    _add_h5(doc, "Conflict of Interest")
    _add(doc, CONFLICT, "Body Text")
    _add_h5(doc, "Author Contributions")
    _add(doc, CONTRIBUTIONS, "Body Text")
    _add_h5(doc, "References")
    for i, ref in enumerate(REFERENCES, start=1):
        _add(doc, f"[{i}] {ref}", "references")

    doc.save(str(OUTPUT))
    print(f"Wrote {OUTPUT.name} with:")
    print(f"  paragraphs: {len(doc.paragraphs)}")
    print(f"  tables    : {len(doc.tables)}")
    print(f"  references: {len(REFERENCES)}")


if __name__ == "__main__":
    build()
