# pytestwaf — System Architecture

Eleven Mermaid architecture diagrams covering the runtime data flow, the ML stack, the multi-cloud autofix pipeline, the codebase module map, and the deployment topology. Each diagram renders directly in VSCode (Markdown Preview Mermaid Support), GitHub, or any Mermaid-aware tool. Pre-rendered PNGs are in [diagrams/](diagrams/).

> **Start here:** Diagram 0 below is the 10-second big-picture overview. Diagrams 1–10 zoom into each part of the system in order.

| # | Diagram | Image |
|---|---|---|
| 00 | **Big-picture overview** (start here) | [PNG](diagrams/00-overview.png) · [.mmd](diagrams/00-overview.mmd) |
| 01 | Comprehensive End-to-End Architecture | [PNG](diagrams/01-end-to-end.png) · [.mmd](diagrams/01-end-to-end.mmd) |
| 02 | Training Architecture | [PNG](diagrams/02-training.png) · [.mmd](diagrams/02-training.mmd) |
| 03 | Prediction / Inference Architecture | [PNG](diagrams/03-prediction.png) · [.mmd](diagrams/03-prediction.mmd) |
| 04 | Response Classification (4-Layer Defense in Depth) | [PNG](diagrams/04-classification.png) · [.mmd](diagrams/04-classification.mmd) |
| 05 | Adaptive Mutation Engine (700 ML Mutations) | [PNG](diagrams/05-mutation.png) · [.mmd](diagrams/05-mutation.mmd) |
| 06 | Autofix → Multi-Cloud IaC Pipeline | [PNG](diagrams/06-autofix-iac.png) · [.mmd](diagrams/06-autofix-iac.mmd) |
| 07 | Cross-Scan Knowledge Persistence | [PNG](diagrams/07-persistence.png) · [.mmd](diagrams/07-persistence.mmd) |
| 08 | Reporting Architecture (HTML / 3D / XLSX / CSV) | [PNG](diagrams/08-reporting.png) · [.mmd](diagrams/08-reporting.mmd) |
| 09 | Full Component Architecture (module map) | [PNG](diagrams/09-full-architecture.png) · [.mmd](diagrams/09-full-architecture.mmd) |
| 10 | Deployment Setup Architecture | [PNG](diagrams/10-deployment.png) · [.mmd](diagrams/10-deployment.mmd) |

---

## 0. Big-picture overview (start here)

The whole system in 9 phases. Read top to bottom. Every other diagram in this document is a zoom-in on one of these boxes.

![0. Big-picture overview](diagrams/00-overview.png)

<details>
<summary>Mermaid source</summary>

```mermaid
---
config:
  theme: base
  themeVariables:
    fontSize: "18px"
    primaryColor: "#ffffff"
    primaryTextColor: "#1a1a1a"
    primaryBorderColor: "#34495e"
    lineColor: "#566573"
    clusterBkg: "#fafbfc"
    clusterBorder: "#bdc3c7"
  flowchart:
    nodeSpacing: 50
    rankSpacing: 60
    curve: basis
---
flowchart TB
    classDef in     fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#0d47a1
    classDef pre    fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    classDef scan   fill:#fff3e0,stroke:#ef6c00,stroke-width:2px,color:#bf360c
    classDef ml     fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px,color:#4a148c
    classDef adapt  fill:#fce4ec,stroke:#ad1457,stroke-width:2px,color:#880e4f
    classDef fix    fill:#e1f5fe,stroke:#0277bd,stroke-width:2px,color:#01579b
    classDef report fill:#f1f8e9,stroke:#558b2f,stroke-width:2px,color:#33691e
    classDef store  fill:#e0f7fa,stroke:#00838f,stroke-width:2px,color:#006064

    A["<b>1 · INPUT</b><br/>You give it a URL<br/>e.g. https://app.example.com"]:::in
    B["<b>2 · PRE-FLIGHT</b><br/>Identify the WAF in front of the app<br/>Capture 3 baseline responses<br/>Load any prior knowledge"]:::pre
    C["<b>3 · SCAN</b><br/>Fire 1,110 attack payloads<br/>SQLi · XSS · LFI · RCE · XXE · SSRF · ..."]:::scan
    D["<b>4 · CLASSIFY each response</b><br/>4-layer pipeline:<br/>WAF regex → baseline diff → autoencoder → online ML<br/><b>blocked / bypassed / unresolved</b>"]:::scan
    E["<b>5 · LEARN from results</b><br/>Train an ML ensemble (RF + GB + MLP)<br/>on what bypassed vs what got blocked"]:::ml
    F["<b>6 · ATTACK AGAIN smartly</b><br/>Generate 700 AI mutations from successful patterns<br/>Score each · fire highest-probability first<br/>Discover new bypasses"]:::adapt
    G["<b>7 · GENERATE FIXES</b><br/>For each bypass · recommend a WAF rule<br/>Emit deployable IaC for AWS · Azure · GCP"]:::fix
    H["<b>8 · REPORT</b><br/>HTML with 27 charts + 3D attack-surface<br/>XLSX · CSV · JSON · IaC · deploy_fix.py"]:::report
    I["<b>9 · REMEMBER for next time</b><br/>Save trained model + bypass patterns<br/>~/.gotestwaf/models/&lt;waf&gt;/<br/>Next scan against same WAF starts smarter"]:::store

    A --> B --> C --> D --> E --> F --> G --> H
    E --> I
    I -. warm-start .-> B
    F -. discoveries .-> D
```

</details>

---

## 1. Comprehensive End-to-End Architecture

The full lifecycle of one scan: CLI invocation → pre-flight → corpus expansion → scanning → ML learning → adaptive mutation → autofix/IaC → HTML/3D report → cross-scan persistence.

![1. Comprehensive End-to-End Architecture](diagrams/01-end-to-end.png)

<details>
<summary>Mermaid source</summary>

```mermaid
---
config:
  theme: base
  themeVariables:
    fontSize: "15px"
    primaryColor: "#ffffff"
    primaryTextColor: "#1a1a1a"
    primaryBorderColor: "#34495e"
    lineColor: "#566573"
    clusterBkg: "#fafbfc"
    clusterBorder: "#bdc3c7"
---
flowchart TB
    classDef cli       fill:#e3f2fd,stroke:#1565c0,stroke-width:1.5px,color:#0d47a1
    classDef pre       fill:#e8f5e9,stroke:#2e7d32,stroke-width:1.5px,color:#1b5e20
    classDef corpus    fill:#fff8e1,stroke:#f9a825,stroke-width:1.5px,color:#594300
    classDef scan      fill:#fff3e0,stroke:#ef6c00,stroke-width:1.5px,color:#bf360c
    classDef ml        fill:#f3e5f5,stroke:#6a1b9a,stroke-width:1.5px,color:#4a148c
    classDef adapt     fill:#fce4ec,stroke:#ad1457,stroke-width:1.5px,color:#880e4f
    classDef infer     fill:#ede7f6,stroke:#4527a0,stroke-width:1.5px,color:#311b92
    classDef fix       fill:#e1f5fe,stroke:#0277bd,stroke-width:1.5px,color:#01579b
    classDef report    fill:#f1f8e9,stroke:#558b2f,stroke-width:1.5px,color:#33691e
    classDef store     fill:#e0f7fa,stroke:#00838f,stroke-width:1.5px,color:#006064

    CLI["Typer CLI · cli/main.py<br/>--targets URLs.txt --reportPath ..."]:::cli
    PRE_BOT["Bot / CAPTCHA detection"]:::pre
    PRE_BL["Baseline capture<br/>3 benign requests + autoencoder train"]:::pre
    PRE_WAF["WAF identification<br/>scanner/waf_detector/"]:::pre
    PRE_LOAD["Cross-scan model load<br/>~/.gotestwaf/models/&lt;waf&gt;/"]:::store

    CORPUS["Test corpus<br/>encoders × placeholders → 1110 cases"]:::corpus

    SCAN["Async scanner pool<br/>scanner/scanner.py · 5 workers"]:::scan
    CLASSIFY["4-layer classification<br/>regex → Jaccard → autoencoder → online ML"]:::scan

    ML_TRAIN["HybridMLEngine.train<br/>Stacking RF + GB + MLP → LogReg<br/>+ isotonic calibration"]:::ml
    ML_METRICS["TrainingMetrics<br/>cv_f1 · per-class P/R/F1 · reliability"]:::ml

    ADAPT["Adaptive mutation · 700 tests<br/>AI payload generator + ML scoring"]:::adapt

    INFER["Ruleset inference<br/>detected vs missing rulesets"]:::infer

    FIX_AF["generate_autofix<br/>multi_cloud: aws + azure + gcp"]:::fix
    FIX_IAC["generate_iac_files<br/>6 deployable artifacts"]:::fix

    REPORT_PREP["Report aggregation<br/>report/html.py"]:::report
    REPORT_OUT["HTML + 27 charts + 3D + XLSX/CSV/JSON"]:::report

    PERSIST["save_scan_knowledge<br/>+ save_ml_model · atomic"]:::store

    CLI --> PRE_BOT --> PRE_BL --> PRE_WAF --> PRE_LOAD --> CORPUS
    CORPUS --> SCAN --> CLASSIFY
    CLASSIFY --> ML_TRAIN --> ML_METRICS
    ML_METRICS --> ADAPT
    ADAPT -.discoveries.-> CLASSIFY
    CLASSIFY --> INFER
    ML_METRICS --> FIX_AF
    INFER --> FIX_AF --> FIX_IAC
    ML_METRICS --> REPORT_PREP
    INFER --> REPORT_PREP
    FIX_AF --> REPORT_PREP
    REPORT_PREP --> REPORT_OUT
    ML_METRICS --> PERSIST
    INFER --> PERSIST
    PERSIST -.warm-start next scan.-> PRE_LOAD
```

</details>

---

## 2. Training Architecture

How the HybridMLEngine learns from in-flight scan results. Stacking ensemble (RF + GB + MLP) with isotonic calibration, balanced sample weights, and stratified cross-validation. Falls back to RF-only when minority class < 10 samples.

![2. Training Architecture](diagrams/02-training.png)

<details>
<summary>Mermaid source</summary>

```mermaid
---
config:
  theme: base
  themeVariables:
    fontSize: "15px"
    primaryColor: "#ffffff"
    primaryTextColor: "#1a1a1a"
    primaryBorderColor: "#34495e"
    lineColor: "#566573"
    clusterBkg: "#fafbfc"
    clusterBorder: "#bdc3c7"
---
flowchart TB
    classDef input  fill:#e3f2fd,stroke:#1565c0,stroke-width:1.5px,color:#0d47a1
    classDef feat   fill:#e8f5e9,stroke:#2e7d32,stroke-width:1.5px,color:#1b5e20
    classDef gate   fill:#fff8e1,stroke:#f9a825,stroke-width:1.5px,color:#594300
    classDef base   fill:#f3e5f5,stroke:#6a1b9a,stroke-width:1.5px,color:#4a148c
    classDef stack  fill:#ede7f6,stroke:#4527a0,stroke-width:1.5px,color:#311b92
    classDef cal    fill:#fff3e0,stroke:#ef6c00,stroke-width:1.5px,color:#bf360c
    classDef cv     fill:#e1f5fe,stroke:#0277bd,stroke-width:1.5px,color:#01579b
    classDef out    fill:#e0f7fa,stroke:#00838f,stroke-width:1.5px,color:#006064

    subgraph S1["1 · Inputs (per test case)"]
        direction LR
        I1["Payload string"]:::input
        I2["HTTP response<br/>status · body · headers"]:::input
        I3["Outcome label<br/>0 = blocked · 1 = bypassed"]:::input
    end

    subgraph S2["2 · Feature engineering"]
        direction LR
        FX1["extract_payload_features<br/>length · entropy · special-char ratio<br/>HTML/SQL/RCE keywords · encoding depth"]:::feat
        FX2["extract_response_features<br/>status · body diff vs baseline<br/>stable-token Jaccard · WAF signal"]:::feat
        FX3["Concatenated vector · ~30 dims"]:::feat
    end

    subgraph S3["3 · Class balance gate"]
        direction LR
        BW["compute_sample_weight<br/>balanced"]:::gate
        BC{"n_minority &lt; 10 ?"}:::gate
        RF_ONLY["RF-only fallback<br/>_train_rf_only"]:::base
    end

    subgraph S4["4 · Base estimators (parallel)"]
        direction LR
        E1["RandomForest<br/>n=200 · max_depth=6<br/>class_weight=balanced"]:::base
        E2["GradientBoosting<br/>n=120 · subsample=0.8"]:::base
        E3["MLPClassifier<br/>hidden=(48,24) · α=1e-3<br/>early_stopping if n≥10"]:::base
    end

    subgraph S5["5 · Stacking + calibration"]
        direction LR
        ST1["StackingClassifier<br/>passthrough=False"]:::stack
        ST2["Meta-learner<br/>LogisticRegression<br/>C=0.5 · balanced"]:::stack
        CV{"sklearn version"}:::cal
        CAL_NEW["FrozenEstimator<br/>sklearn ≥ 1.6"]:::cal
        CAL_OLD["cv='prefit'<br/>sklearn ≤ 1.5"]:::cal
        CAL["CalibratedClassifierCV<br/>method = isotonic"]:::cal
    end

    subgraph S6["6 · Cross-validation"]
        direction LR
        K1["StratifiedKFold<br/>cv = min(5, n_minority)"]:::cv
        K2["cross_val_predict · OOF probabilities"]:::cv
        K3["Per-fold F1 → cv_f1_score"]:::cv
    end

    subgraph S7["7 · TrainingMetrics output"]
        direction LR
        M1["cv_f1_score (mean)"]:::out
        M2["per_class P / R / F1"]:::out
        M3["10-bin reliability<br/>(calibration plot)"]:::out
        M4["confusion matrix"]:::out
        M5["feature_contributions"]:::out
    end

    subgraph S8["8 · Persistence"]
        direction LR
        SV1["save_ml_model<br/>tempfile + os.replace · atomic"]:::out
        SV2["~/.gotestwaf/models/&lt;waf&gt;/<br/>engine.joblib + meta.json"]:::out
    end

    I1 --> FX1
    I2 --> FX2
    FX1 --> FX3
    FX2 --> FX3
    I3 --> BW
    FX3 --> BC
    BC -- yes --> RF_ONLY --> K1
    BC -- no --> E1
    BC -- no --> E2
    BC -- no --> E3
    BW --> E1
    BW --> E2
    BW --> E3
    E1 --> ST1
    E2 --> ST1
    E3 --> ST1
    ST1 --> ST2 --> CV
    CV -- newer --> CAL_NEW --> CAL
    CV -- older --> CAL_OLD --> CAL
    CAL --> K1 --> K2 --> K3
    K3 --> M1
    K3 --> M2
    K3 --> M3
    K3 --> M4
    K3 --> M5
    M1 --> SV1 --> SV2
```

</details>

---

## 3. Prediction / Inference Architecture

How the trained calibrated ensemble scores payloads at runtime. Two paths: (a) **fast mode** — load prior model and reorder upcoming payloads by predicted bypass probability; (b) **adaptive round** — score AI-generated mutations, fire highest-scoring first.

![3. Prediction / Inference Architecture](diagrams/03-prediction.png)

<details>
<summary>Mermaid source</summary>

```mermaid
---
config:
  theme: base
  themeVariables:
    fontSize: "15px"
    primaryColor: "#ffffff"
    primaryTextColor: "#1a1a1a"
    primaryBorderColor: "#34495e"
    lineColor: "#566573"
    clusterBkg: "#fafbfc"
    clusterBorder: "#bdc3c7"
---
flowchart TB
    classDef load   fill:#e3f2fd,stroke:#1565c0,stroke-width:1.5px,color:#0d47a1
    classDef gate   fill:#fff8e1,stroke:#f9a825,stroke-width:1.5px,color:#594300
    classDef pred   fill:#f3e5f5,stroke:#6a1b9a,stroke-width:1.5px,color:#4a148c
    classDef fast   fill:#e8f5e9,stroke:#2e7d32,stroke-width:1.5px,color:#1b5e20
    classDef adapt  fill:#fce4ec,stroke:#ad1457,stroke-width:1.5px,color:#880e4f
    classDef cold   fill:#eceff1,stroke:#546e7a,stroke-width:1.5px,color:#263238

    subgraph S1["1 · Model load (startup)"]
        FAST_FLAG{"--mlFast set ?"}:::gate
        LOAD["load_ml_model<br/>model_store.py"]:::load
        AGE["age &lt; 30 days ?"]:::gate
        F1{"cv_f1_score ≥ 0.5 ?"}:::gate
        SK["sklearn version match ?"]:::gate
        LOADED["joblib.load → engine.joblib<br/>warm engine ready"]:::load
        COLD["Cold start<br/>train from this scan"]:::cold
    end

    subgraph S2["2 · Per-payload prediction"]
        P1["Candidate payload + context"]:::pred
        P2["extract_payload_features · 30 dims"]:::pred
        P3["StandardScaler.transform"]:::pred
        P4["calibrated_classifiers_[0].estimator<br/>predict_proba"]:::pred
        P5["Inner stacking · RF + GB + MLP votes"]:::pred
        P6["LogReg meta combines"]:::pred
        P7["Isotonic calibration map"]:::pred
        P8["bypass_probability ∈ [0, 1]"]:::pred
    end

    subgraph S3["3 · Batch scoring"]
        B1["score_payloads_batch · N items"]:::pred
        B2["Vectorised predict_proba"]:::pred
        B3["Sorted scores ↓"]:::pred
    end

    subgraph S4["4a · Fast-mode reorder · main scan"]
        FA1["_apply_ml_fast_filter"]:::fast
        FA2{"score &gt; mlFastThreshold ?"}:::gate
        FA3["Drop payload"]:::cold
        FA4["Reorder · high → low"]:::fast
        FA5["Scanner queue priority"]:::fast
    end

    subgraph S5["4b · Adaptive round · 700 mutations"]
        AD1["Bypassed combos · encoder × placeholder"]:::adapt
        AD2["generate_ai_payloads · 200+ mutations"]:::adapt
        AD3["Score each mutation"]:::adapt
        AD4["Top-K fire first via ml_worker"]:::adapt
        AD5{"New bypass ?"}:::gate
        AD6["Append to training set"]:::adapt
    end

    FAST_FLAG -- yes --> LOAD --> AGE
    FAST_FLAG -- no --> COLD
    AGE -- stale --> COLD
    AGE -- ok --> F1
    F1 -- low --> COLD
    F1 -- ok --> SK
    SK -.warn only.-> LOADED
    LOADED --> P1

    P1 --> P2 --> P3 --> P4 --> P5 --> P6 --> P7 --> P8
    P8 --> B1 --> B2 --> B3
    B3 --> FA1 --> FA2
    FA2 -- no --> FA3
    FA2 -- yes --> FA4 --> FA5

    AD1 --> AD2 --> AD3 --> AD4 --> AD5
    AD5 -- yes --> AD6
    AD3 -.uses.-> P4
```

</details>

---

## 4. Response Classification (4-Layer Defense in Depth)

The decision pipeline that turns a single HTTP response into blocked, passed, or unresolved. Every layer is independent and can override; tightening this fixed the TN=0% bug.

![4. Response Classification (4-Layer Defense in Depth)](diagrams/04-classification.png)

<details>
<summary>Mermaid source</summary>

```mermaid
---
config:
  theme: base
  themeVariables:
    fontSize: "15px"
    primaryColor: "#ffffff"
    primaryTextColor: "#1a1a1a"
    primaryBorderColor: "#34495e"
    lineColor: "#566573"
    clusterBkg: "#fafbfc"
    clusterBorder: "#bdc3c7"
---
flowchart TB
    classDef start  fill:#eceff1,stroke:#37474f,stroke-width:1.5px,color:#102027
    classDef l1     fill:#e3f2fd,stroke:#1565c0,stroke-width:1.5px,color:#0d47a1
    classDef l2     fill:#e8f5e9,stroke:#2e7d32,stroke-width:1.5px,color:#1b5e20
    classDef l25    fill:#fff3e0,stroke:#ef6c00,stroke-width:1.5px,color:#bf360c
    classDef l3     fill:#f3e5f5,stroke:#6a1b9a,stroke-width:1.5px,color:#4a148c
    classDef gate   fill:#fff8e1,stroke:#f9a825,stroke-width:1.5px,color:#594300
    classDef block  fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#b71c1c
    classDef pass   fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    classDef unres  fill:#fff8e1,stroke:#f9a825,stroke-width:2px,color:#594300

    START(["HTTP response from target<br/>status · body · headers · timing"]):::start

    subgraph L1["Layer 1 · WAF detector regex"]
        D1["check_block_func<br/>from identified WAF"]:::l1
        D2{"matches block signature ?"}:::gate
    end

    subgraph L2["Layer 2 · Baseline similarity"]
        S1["strip dynamic content<br/>nonces · timestamps · CSRF"]:::l2
        S2["tokenize body"]:::l2
        S3["stable-token Jaccard<br/>vs 3-baseline intersection"]:::l2
        S4["WAF keyword score<br/>strong vs soft phrases"]:::l2
        R0{"baseline abnormal<br/>+ high Jaccard ?"}:::gate
        R1{"WAF keywords<br/>+ diff from baseline ?"}:::gate
        R2{"high baseline coverage<br/>+ no WAF keywords ?"}:::gate
    end

    subgraph L25["Layer 2.5 · Response autoencoder"]
        AE1["reconstruct response feature vector"]:::l25
        AE2["MSE reconstruction error"]:::l25
        AE3{"error &gt; threshold<br/>+ status ∈ {200,403,406,429,503} ?"}:::gate
    end

    subgraph L3["Layer 3 · Online ML clustering"]
        ML1["online_ml.get_enhanced_classification"]:::l3
        ML2["real-time response cluster ID"]:::l3
        ML3{"cluster matches known<br/>block-page cluster ?"}:::gate
    end

    OUT_BLOCK_L1["BLOCKED · early-exit"]:::block
    OUT_UNRES_BL["UNRESOLVED · baseline poisoned"]:::unres
    OUT_BLOCK_L2["BLOCKED"]:::block
    OUT_PASS_L2["PASSED"]:::pass
    OUT_BLOCK_AE["BLOCKED · anomalous response"]:::block
    OUT_BLOCK_ML["BLOCKED"]:::block
    OUT_UNRES["UNRESOLVED · defer to post-scan ML"]:::unres

    START --> D1 --> D2
    D2 -- yes --> OUT_BLOCK_L1
    D2 -- no --> S1 --> S2 --> S3 --> S4 --> R0
    R0 -- yes --> OUT_UNRES_BL
    R0 -- no --> R1
    R1 -- yes --> OUT_BLOCK_L2
    R1 -- no --> R2
    R2 -- yes --> OUT_PASS_L2
    R2 -- no --> AE1 --> AE2 --> AE3
    AE3 -- yes --> OUT_BLOCK_AE
    AE3 -- no --> ML1 --> ML2 --> ML3
    ML3 -- yes --> OUT_BLOCK_ML
    ML3 -- no --> OUT_UNRES
```

</details>

---

## 5. Adaptive Mutation Engine (700 ML Mutations)

After the main scan + training, the system uses what it learned to attack again — generates AI payloads from the bypass patterns, scores each, fires highest-probability first.

![5. Adaptive Mutation Engine (700 ML Mutations)](diagrams/05-mutation.png)

<details>
<summary>Mermaid source</summary>

```mermaid
---
config:
  theme: base
  themeVariables:
    fontSize: "15px"
    primaryColor: "#ffffff"
    primaryTextColor: "#1a1a1a"
    primaryBorderColor: "#34495e"
    lineColor: "#566573"
    clusterBkg: "#fafbfc"
    clusterBorder: "#bdc3c7"
---
flowchart TB
    classDef src    fill:#e3f2fd,stroke:#1565c0,stroke-width:1.5px,color:#0d47a1
    classDef gen    fill:#f3e5f5,stroke:#6a1b9a,stroke-width:1.5px,color:#4a148c
    classDef score  fill:#fff3e0,stroke:#ef6c00,stroke-width:1.5px,color:#bf360c
    classDef fire   fill:#fce4ec,stroke:#ad1457,stroke-width:1.5px,color:#880e4f
    classDef learn  fill:#e0f7fa,stroke:#00838f,stroke-width:1.5px,color:#006064
    classDef gate   fill:#fff8e1,stroke:#f9a825,stroke-width:1.5px,color:#594300

    subgraph S1["1 · Bypass evidence from main scan"]
        direction LR
        E1["Bypassed test cases"]:::src
        E2["Encoder × placeholder combos<br/>bypass_rate &gt; 10%"]:::src
        E3["Top-30 successful payloads"]:::src
    end

    subgraph S2["2 · AI payload generator · ml/payload_generator.py"]
        direction LR
        G1["Pattern reuse<br/>successful templates"]:::gen
        G2["Encoding chains<br/>URL+B64 · double · triple"]:::gen
        G3["Cross-category transfer<br/>XSS template → SQLi context"]:::gen
        G4["Structural mutation<br/>case mix · comments · null bytes"]:::gen
        G5["~700 candidate mutations"]:::gen
    end

    subgraph S3["3 · ML scoring"]
        direction LR
        SC1["score_payloads_batch"]:::score
        SC2["bypass_probability per mutation"]:::score
        SC3["Sort high → low"]:::score
    end

    subgraph S4["4 · ml_worker async pool"]
        direction LR
        F1["Skip combos · online ML flagged 'always blocked'"]:::fire
        F2["Skip non-ASCII · httpx limitation"]:::fire
        F3["_send_payload"]:::fire
        F4["Re-classify response · same 4-layer pipeline"]:::fire
    end

    subgraph S5["5 · Discovery loop"]
        direction LR
        D1{"new bypass ?"}:::gate
        D2["ml_bypasses ++"]:::learn
        D3["Append to training set"]:::learn
        D4["Update bypass_patterns dict"]:::learn
    end

    E1 --> G1
    E2 --> G2
    E3 --> G3
    E2 --> G4
    G1 --> G5
    G2 --> G5
    G3 --> G5
    G4 --> G5
    G5 --> SC1 --> SC2 --> SC3
    SC3 --> F1 --> F2 --> F3 --> F4 --> D1
    D1 -- yes --> D2 --> D3 --> D4
    D4 -.feeds next scan.-> E1
```

</details>

---

## 6. Autofix → Multi-Cloud IaC Pipeline

How bypassed categories + missing-ruleset inference become deployable Terraform / CloudFormation / Bicep / gcloud artifacts. AWS + Azure + GCP are emitted regardless of detected WAF — SREs on any cloud can pick the right deploy file.

![6. Autofix → Multi-Cloud IaC Pipeline](diagrams/06-autofix-iac.png)

<details>
<summary>Mermaid source</summary>

```mermaid
---
config:
  theme: base
  themeVariables:
    fontSize: "15px"
    primaryColor: "#ffffff"
    primaryTextColor: "#1a1a1a"
    primaryBorderColor: "#34495e"
    lineColor: "#566573"
    clusterBkg: "#fafbfc"
    clusterBorder: "#bdc3c7"
---
flowchart TB
    classDef input  fill:#e3f2fd,stroke:#1565c0,stroke-width:1.5px,color:#0d47a1
    classDef logic  fill:#f3e5f5,stroke:#6a1b9a,stroke-width:1.5px,color:#4a148c
    classDef aws    fill:#fff3e0,stroke:#ef6c00,stroke-width:1.5px,color:#bf360c
    classDef azure  fill:#e1f5fe,stroke:#0277bd,stroke-width:1.5px,color:#01579b
    classDef gcp    fill:#fce4ec,stroke:#ad1457,stroke-width:1.5px,color:#880e4f
    classDef out    fill:#e8f5e9,stroke:#2e7d32,stroke-width:1.5px,color:#1b5e20

    subgraph S1["1 · Inputs"]
        direction LR
        I1["bypassed_categories<br/>{ sqli, xss, lfi, rce, ... }"]:::input
        I2["InferenceResult<br/>detected vs missing rulesets"]:::input
        I3["waf_name"]:::input
    end

    subgraph S2["2 · report/autofix.py"]
        direction TB
        AF1["generate_autofix"]:::logic
        AF2["primary fixes<br/>WAF-specific recommendations"]:::logic
        AFA["_generate_aws_fixes · 4 fixes"]:::aws
        AFZ["_generate_azure_fixes · 7 fixes"]:::azure
        AFG["_generate_gcp_fixes · 6 fixes"]:::gcp
        MC["multi_cloud · aws + azure + gcp"]:::logic
        AWSR["aws_rules · boto3 dict spec"]:::aws
    end

    subgraph S3["3 · report/iac_generator.py"]
        direction TB
        IG1["generate_iac_files"]:::logic
        IGA1["_generate_terraform_aws<br/>aws_wafv2_web_acl"]:::aws
        IGA2["_generate_cloudformation_aws<br/>AWS::WAFv2::WebACL"]:::aws
        IGZ1["_generate_bicep_azure<br/>Microsoft.Network FrontDoor WAF"]:::azure
        IGZ2["_generate_az_cli_script"]:::azure
        IGG1["_generate_terraform_gcp<br/>google_compute_security_policy<br/>(CEL · single-quote)"]:::gcp
        IGG2["_generate_gcloud_script"]:::gcp
    end

    subgraph S4["4 · cli/main.py · boto3 deploy script"]
        direction TB
        D1["_generate_boto3_deploy_script"]:::logic
        D2["NEW_RULES = json.loads(r-string)<br/>JSON true/false → Python True/False"]:::logic
        D3["List + pick Web ACL"]:::aws
        D4["Merge rules · no overwrite"]:::aws
        D5["update_web_acl"]:::aws
    end

    subgraph S5["5 · Artifacts written next to report"]
        direction LR
        O1[".tf · AWS Terraform"]:::out
        O2[".yaml · CloudFormation"]:::out
        O3[".bicep · Azure"]:::out
        O4[".sh · az CLI"]:::out
        O5[".tf · GCP Terraform"]:::out
        O6[".sh · gcloud"]:::out
        O7[".py · boto3 deploy"]:::out
        O8[".json · autofix"]:::out
    end

    I1 --> AF1
    I2 --> AF1
    I3 --> AF1
    AF1 --> AF2
    AF1 --> AFA
    AF1 --> AFZ
    AF1 --> AFG
    AFA --> AWSR
    AFA --> MC
    AFZ --> MC
    AFG --> MC

    AWSR --> IG1
    MC --> IG1
    IG1 --> IGA1
    IG1 --> IGA2
    IG1 --> IGZ1
    IG1 --> IGZ2
    IG1 --> IGG1
    IG1 --> IGG2

    AWSR --> D1 --> D2 --> D3 --> D4 --> D5

    IGA1 --> O1
    IGA2 --> O2
    IGZ1 --> O3
    IGZ2 --> O4
    IGG1 --> O5
    IGG2 --> O6
    D2 --> O7
    MC --> O8
```

</details>

---

## 7. Cross-Scan Knowledge Persistence

The system gets smarter every scan. Bypass patterns + trained models are keyed by WAF type and reused on the next scan against the same family.

![7. Cross-Scan Knowledge Persistence](diagrams/07-persistence.png)

<details>
<summary>Mermaid source</summary>

```mermaid
---
config:
  theme: base
  themeVariables:
    fontSize: "15px"
    primaryColor: "#ffffff"
    primaryTextColor: "#1a1a1a"
    primaryBorderColor: "#34495e"
    lineColor: "#566573"
    clusterBkg: "#fafbfc"
    clusterBorder: "#bdc3c7"
---
flowchart TB
    classDef scan   fill:#e3f2fd,stroke:#1565c0,stroke-width:1.5px,color:#0d47a1
    classDef store  fill:#f3e5f5,stroke:#6a1b9a,stroke-width:1.5px,color:#4a148c
    classDef fs     fill:#fff8e1,stroke:#f9a825,stroke-width:1.5px,color:#594300
    classDef next   fill:#e8f5e9,stroke:#2e7d32,stroke-width:1.5px,color:#1b5e20
    classDef gate   fill:#fff3e0,stroke:#ef6c00,stroke-width:1.5px,color:#bf360c

    subgraph S1["1 · Scan #N completes"]
        direction LR
        A1["bypass_patterns dict"]:::scan
        A2["HybridMLEngine · trained + calibrated"]:::scan
        A3["InferenceResult · missing rulesets"]:::scan
    end

    subgraph S2["2 · Persistence layer · ml/model_store.py"]
        direction LR
        P0["_get_waf_key<br/>aws-waf · azure-fd · ..."]:::store
        P1["save_scan_knowledge"]:::store
        P2["save_ml_model<br/>tempfile + os.replace · atomic"]:::store
        P3["scan_history append-only"]:::store
    end

    subgraph S3["3 · Filesystem · ~/.gotestwaf/models/&lt;waf&gt;/"]
        direction LR
        F1["knowledge.json<br/>bypass patterns + metadata"]:::fs
        F2["engine.joblib<br/>serialised CalibratedClassifierCV"]:::fs
        F3["engine.meta.json<br/>cv_f1 · sklearn version · age"]:::fs
        F4["scan_history.jsonl<br/>append per scan"]:::fs
    end

    subgraph S4["4 · Scan #N+1 · same WAF type"]
        direction LR
        L1["load_scan_knowledge"]:::next
        L2["get_priority_payloads<br/>combos with rate &gt; 0.1"]:::next
        L3["load_ml_model"]:::next
        G{"gate · age &lt; 30d<br/>+ cv_f1 ≥ 0.5"}:::gate
        L5["score_payloads_batch<br/>warm-start"]:::next
        L6["fall back to cold training"]:::next
    end

    A1 --> P1
    A2 --> P2
    A3 --> P1
    P0 --> P1
    P0 --> P2
    P1 --> F1
    P1 --> P3 --> F4
    P2 --> F2
    P2 --> F3

    F1 --> L1 --> L2
    F2 --> L3 --> G
    G -- pass --> L5
    G -- fail --> L6
```

</details>

---

## 8. Reporting Architecture (HTML / 3D / XLSX / CSV)

How scan output, ML metrics, ruleset inference, and autofix data are funnelled into the publication-quality HTML report (27 charts, 3D attack-surface scene, MITRE mapping, light-theme + 2× DPR PNG export).

![8. Reporting Architecture (HTML / 3D / XLSX / CSV)](diagrams/08-reporting.png)

<details>
<summary>Mermaid source</summary>

```mermaid
---
config:
  theme: base
  themeVariables:
    fontSize: "15px"
    primaryColor: "#ffffff"
    primaryTextColor: "#1a1a1a"
    primaryBorderColor: "#34495e"
    lineColor: "#566573"
    clusterBkg: "#fafbfc"
    clusterBorder: "#bdc3c7"
---
flowchart TB
    classDef src    fill:#e3f2fd,stroke:#1565c0,stroke-width:1.5px,color:#0d47a1
    classDef prep   fill:#f3e5f5,stroke:#6a1b9a,stroke-width:1.5px,color:#4a148c
    classDef three  fill:#fff3e0,stroke:#ef6c00,stroke-width:1.5px,color:#bf360c
    classDef chart  fill:#fce4ec,stroke:#ad1457,stroke-width:1.5px,color:#880e4f
    classDef out    fill:#e8f5e9,stroke:#2e7d32,stroke-width:1.5px,color:#1b5e20

    subgraph S1["1 · Data sources"]
        direction LR
        D1["Statistics<br/>score · TP / TN / FP"]:::src
        D2["TrainingMetrics<br/>cv_f1 · per-class · calibration bins"]:::src
        D3["InferenceResult<br/>detected / missing rulesets"]:::src
        D4["Compliance results<br/>PCI-DSS · SOC2 · ISO27001 · NIST"]:::src
        D5["Autofix dict<br/>multi_cloud"]:::src
        D6["Scan history · diff vs prior scan"]:::src
    end

    subgraph S2["2 · report/html.py"]
        direction LR
        H1["prepare_html_full_report"]:::prep
        H2["aggregate all sources"]:::prep
        H3["compute per-set grades"]:::prep
        H4["once_prepare_html_full_report<br/>thread-safe cache"]:::prep
    end

    subgraph S3["3 · report/report3d.py"]
        direction LR
        T1["generate_3d_html_report"]:::three
        T2["27 chart canvases"]:::three
        T3["Three.js attack-surface scene"]:::three
        T4["MITRE ATT&amp;CK overlay"]:::three
        T5["Light theme · Helvetica · DPR=2"]:::three
    end

    subgraph S4["4 · Chart groups"]
        direction LR
        C1["Scan summary<br/>blocked · bypassed · unresolved"]:::chart
        C2["ML predictions<br/>P / R / F1 · calibration · CDF<br/>confidence · top-risk · mut. eff."]:::chart
        C3["Compliance heatmap"]:::chart
        C4["Bypass categories breakdown"]:::chart
        C5["Autofix recommendations panel"]:::chart
    end

    subgraph S5["5 · Other exports"]
        direction LR
        X1["XLSX · openpyxl"]:::out
        X2["CSV per category"]:::out
        X3["JSON full scan dump"]:::out
    end

    D1 --> H1
    D2 --> H1
    D3 --> H1
    D4 --> H1
    D5 --> H1
    D6 --> H1
    H1 --> H2 --> H3 --> H4
    H4 --> T1
    T1 --> T2
    T1 --> T3
    T1 --> T4
    T1 --> T5
    T2 --> C1
    T2 --> C2
    T2 --> C3
    T2 --> C4
    T2 --> C5
    H4 --> X1
    H4 --> X2
    H4 --> X3
```

</details>

---

## 9. Full Component Architecture (module map)

A package-level map of the codebase: which modules live in cli/, helpers/, scanner/, ml/, report/, and how they wire together. Use this as the orientation map when reading the source.

![9. Full Component Architecture (module map)](diagrams/09-full-architecture.png)

<details>
<summary>Mermaid source</summary>

```mermaid
---
config:
  theme: base
  themeVariables:
    fontSize: "14px"
    primaryColor: "#ffffff"
    primaryTextColor: "#1a1a1a"
    primaryBorderColor: "#34495e"
    lineColor: "#566573"
    clusterBkg: "#fafbfc"
    clusterBorder: "#bdc3c7"
  flowchart:
    nodeSpacing: 35
    rankSpacing: 55
    curve: basis
---
flowchart TB
    classDef cli       fill:#e3f2fd,stroke:#1565c0,stroke-width:1.5px,color:#0d47a1
    classDef helpers   fill:#fff8e1,stroke:#f9a825,stroke-width:1.5px,color:#594300
    classDef scanner   fill:#fff3e0,stroke:#ef6c00,stroke-width:1.5px,color:#bf360c
    classDef ml        fill:#f3e5f5,stroke:#6a1b9a,stroke-width:1.5px,color:#4a148c
    classDef report    fill:#e8f5e9,stroke:#2e7d32,stroke-width:1.5px,color:#1b5e20
    classDef data      fill:#e0f7fa,stroke:#00838f,stroke-width:1.5px,color:#006064
    classDef ext       fill:#eceff1,stroke:#546e7a,stroke-width:1.5px,color:#263238
    classDef alert     fill:#fce4ec,stroke:#ad1457,stroke-width:1.5px,color:#880e4f

    CLI["<b>cli/main.py</b><br/>Typer entry · batch · single-target<br/>60+ flags"]:::cli

    HELPERS["<b>helpers/</b><br/>http.py · auth.py · email.py<br/>baseline_cache.py · harvest_cookies.py"]:::helpers

    CORPUS["<b>config/ + testcases/</b><br/>~50 categories · YAML payload DB<br/>encoders × placeholders → 1110 cases"]:::data

    SCANNER["<b>scanner/scanner.py</b><br/>async pool · main + adaptive scan"]:::scanner
    SCAN_SUB["<b>scanner sub-modules</b><br/>types/ · waf_detector/ (50+ vendors)<br/>ruleset_inference · online_ml<br/>grpc · graphql · rate_limit · cve · bot"]:::scanner

    ML_ENG["<b>ml/engine.py</b><br/>HybridMLEngine<br/>Stacking RF + GB + MLP → LogReg<br/>+ isotonic calibration"]:::ml
    ML_SUB["<b>ml sub-modules</b><br/>features.py · bypass_predictor.py<br/>payload_generator.py · response_autoencoder.py<br/>model_store.py"]:::ml

    REPORT["<b>report/html.py</b><br/>aggregator · prepare_html_full_report"]:::report
    REPORT_SUB["<b>report sub-modules</b><br/>report3d.py · 27 charts + Three.js<br/>autofix.py · iac_generator.py<br/>compliance · mitre · xlsx · csv · json"]:::report

    OUT_FS["<b>./reports/</b><br/>HTML · IaC · autofix.json<br/>deploy_fix.py · XLSX · CSV"]:::data
    OUT_MOD["<b>~/.gotestwaf/models/&lt;waf&gt;/</b><br/>engine.joblib · knowledge.json<br/>scan_history · meta.json"]:::data
    OUT_LOG["structured stdout logs"]:::data

    NOTIFY["<b>Notifications</b><br/>Slack webhook · Teams webhook<br/>SMTP recipient"]:::alert

    EXT["<b>External Python deps</b><br/>scikit-learn 1.8 · joblib · httpx · gohttp<br/>typer · rich · jinja2 · openpyxl · structlog<br/>boto3 (deploy_fix runtime only)"]:::ext

    CLI --> CORPUS
    CLI --> HELPERS
    CLI --> SCANNER
    SCANNER --> SCAN_SUB
    HELPERS --> SCANNER

    SCANNER --> ML_ENG
    ML_ENG --> ML_SUB

    SCANNER --> REPORT
    ML_ENG --> REPORT
    REPORT --> REPORT_SUB
    REPORT_SUB -.feeds back.-> CLI

    REPORT --> OUT_FS
    REPORT_SUB --> OUT_FS
    ML_SUB --> OUT_MOD
    OUT_MOD -. warm-start .-> ML_SUB

    CLI --> OUT_LOG
    CLI --> NOTIFY

    ML_ENG -. uses .-> EXT
    HELPERS -. uses .-> EXT
    REPORT -. uses .-> EXT
    CLI -. uses .-> EXT
```

</details>

---

## 10. Deployment Setup Architecture

How pytestwaf runs in production: trigger surface (CLI / cron / CI), Docker image, container process, volume mounts, network egress, secrets, notifications, and the separate operator-driven deploy path that applies the generated IaC.

![10. Deployment Setup Architecture](diagrams/10-deployment.png)

<details>
<summary>Mermaid source</summary>

```mermaid
---
config:
  theme: base
  themeVariables:
    fontSize: "14px"
    primaryColor: "#ffffff"
    primaryTextColor: "#1a1a1a"
    primaryBorderColor: "#34495e"
    lineColor: "#566573"
    clusterBkg: "#fafbfc"
    clusterBorder: "#bdc3c7"
  flowchart:
    nodeSpacing: 35
    rankSpacing: 55
    curve: basis
---
flowchart TB
    classDef trigger fill:#fff3e0,stroke:#ef6c00,stroke-width:1.5px,color:#bf360c
    classDef host    fill:#e3f2fd,stroke:#1565c0,stroke-width:1.5px,color:#0d47a1
    classDef docker  fill:#e1f5fe,stroke:#0277bd,stroke-width:2px,color:#01579b
    classDef proc    fill:#f3e5f5,stroke:#6a1b9a,stroke-width:1.5px,color:#4a148c
    classDef vol     fill:#fff8e1,stroke:#f9a825,stroke-width:1.5px,color:#594300
    classDef target  fill:#fce4ec,stroke:#ad1457,stroke-width:1.5px,color:#880e4f
    classDef out     fill:#e8f5e9,stroke:#2e7d32,stroke-width:1.5px,color:#1b5e20
    classDef secret  fill:#eceff1,stroke:#546e7a,stroke-width:1.5px,color:#263238
    classDef deploy  fill:#ede7f6,stroke:#4527a0,stroke-width:1.5px,color:#311b92

    TRIG["<b>1 · Trigger surface</b><br/>Operator CLI · docker run pytestwaf:r17<br/>Scheduler · cron / Task Scheduler<br/>CI runner · GitHub Actions nightly"]:::trigger

    SECRETS["<b>2 · Credentials &amp; secrets injected</b><br/>--cookie · --authHeader · --loginURL · --loginBody<br/>SMTP credentials (env)<br/>AWS keys (deploy_fix.py runtime only)"]:::secret

    HOST["<b>3 · Host machine</b><br/>Windows / Linux / macOS<br/>Docker Engine · Desktop on Windows · daemon on Linux"]:::host

    IMG["<b>4 · Docker image · pytestwaf:r17</b><br/>python:3.13-slim<br/>scikit-learn 1.8 · joblib · httpx · typer<br/>jinja2 · openpyxl · structlog<br/>/app/ · cli/ · scanner/ · ml/ · report/ · testcases/<br/>ENTRYPOINT: python -m gotestwaf"]:::docker

    CONT["<b>5 · Docker container · gotestwaf process</b><br/>Typer entry · async event loop<br/>5 async workers · scanner/scanner.py<br/>sklearn ensemble in-memory<br/>RF + GB + MLP + LogReg + isotonic"]:::proc

    MNT_IN["<b>6a · Volume mounts (input)</b><br/>./URLs.txt :ro · target list<br/>./config.yaml :ro · optional override"]:::vol
    MNT_OUT["<b>6b · Volume mounts (output)</b><br/>./reports/ :rw · HTML · IaC · autofix · deploy_fix.py<br/>~/.gotestwaf/models/ :rw · cross-scan persistence"]:::vol

    NET["<b>7 · Network egress</b><br/>DNS resolution<br/>Optional HTTP proxy · --proxy<br/>HTTPS · 1110 + 700 requests"]:::secret
    TGT["<b>8 · Target WAF / origin</b><br/>(application under test)"]:::target

    NOTIFY["<b>9 · Notification fan-out</b><br/>Slack webhook · Teams webhook<br/>SMTP recipient · structured stdout logs"]:::out

    DEP["<b>10 · Deploy path · operator runs separately, after scan</b><br/>python deploy_fix.py · boto3 merges into existing Web ACL<br/>terraform apply · aws / azure / gcp<br/>aws cloudformation deploy<br/>az deployment group create<br/>gcloud compute security-policies"]:::deploy

    TRIG --> HOST
    SECRETS --> CONT
    HOST --> IMG --> CONT
    MNT_IN --> CONT
    CONT --> MNT_OUT
    MNT_OUT -. warm-start next scan .-> CONT
    CONT -.HTTPS.-> NET --> TGT
    CONT --> NOTIFY
    MNT_OUT --> DEP
    SECRETS -. AWS keys at deploy time .-> DEP
```

</details>

---

## File reference

| Diagram | Primary source files |
|---|---|
| End-to-end | [cli/main.py](../src/gotestwaf/cli/main.py) — orchestrator |
| Training | [ml/engine.py](../src/gotestwaf/ml/engine.py), [ml/bypass_predictor.py](../src/gotestwaf/ml/bypass_predictor.py) |
| Prediction | [ml/engine.py](../src/gotestwaf/ml/engine.py), [ml/model_store.py](../src/gotestwaf/ml/model_store.py) |
| Classification | [scanner/scanner.py](../src/gotestwaf/scanner/scanner.py) — `_check_blocked_or_passed` |
| Mutation | [ml/payload_generator.py](../src/gotestwaf/ml/payload_generator.py), [scanner/scanner.py](../src/gotestwaf/scanner/scanner.py) — `_run_adaptive_scan` |
| Autofix/IaC | [report/autofix.py](../src/gotestwaf/report/autofix.py), [report/iac_generator.py](../src/gotestwaf/report/iac_generator.py) |
| Persistence | [ml/model_store.py](../src/gotestwaf/ml/model_store.py) |
| Reporting | [report/html.py](../src/gotestwaf/report/html.py), [report/report3d.py](../src/gotestwaf/report/report3d.py) |
| Full architecture | entire [src/gotestwaf/](../src/gotestwaf/) tree |
| Deployment | [Dockerfile](../Dockerfile) |

## Re-rendering

After editing a `.mmd` file, regenerate its PNG:

```powershell
npx -p "@mermaid-js/mermaid-cli" mmdc `
  -i docs/diagrams/01-end-to-end.mmd `
  -o docs/diagrams/01-end-to-end.png `
  -b white --scale 2 `
  -p docs/diagrams/puppeteer-config.json
```
