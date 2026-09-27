# pytestwaf — Hybrid ML for Adaptive WAF Validation and Multi-Cloud Auto-Remediation

`pytestwaf` validates a deployed Web Application Firewall by scanning it, learning
its decision boundary in-flight, generating adaptive bypass candidates, and
emitting multi-cloud Infrastructure-as-Code remediation. It is the reference
implementation for the paper *"Hybrid Machine Learning for Adaptive Web
Application Firewall Validation and Multi-Cloud Auto-Remediation"* (Scientific
Reports, under review).

## Attribution

The **request-generation layer** — the attack-payload corpus and the placeholder
and encoder abstractions that turn each payload into a concrete HTTP request — is
a **Python re-implementation of the open-source [GoTestWAF](https://github.com/wallarm/gotestwaf)
project**. Parity tests in `tests/parity/` assert byte-for-byte agreement with the
original for the deterministic encoders.

## Original contributions of this work

These components have no counterpart in GoTestWAF and are the contribution of the
paper:

- **Four-layer response classifier** (`src/.../ml/response_classifier.py`,
  `response_autoencoder.py`) — vendor-signature, baseline-similarity, autoencoder
  anomaly, and online-clustering layers.
- **Calibrated in-flight stacking ensemble** (`ml/engine.py`, `bypass_predictor.py`)
  — Random Forest + Gradient Boosting + MLP with a logistic-regression meta-learner
  and isotonic calibration.
- **Adaptive mutation engine** (`ml/payload_generator.py`).
- **Multi-cloud IaC remediation** (`report/iac_generator.py`, `report/autofix.py`)
  — Terraform, CloudFormation, Bicep, gcloud, and a boto3 non-destructive merge.
- **Ruleset inference and compliance mapping** (`scanner/ruleset_inference.py`,
  `report/compliance.py`).
- **Cross-scan persistence** (`ml/model_store.py`).

## Reproducing the paper's results

The scan datasets and figure scripts are archived with this release on Zenodo
(see Data/Code Availability in the paper). `regenerate_figures.py` rebuilds every
data figure from the released CSVs.

## Install & run

```
pip install -e .
pytestwaf --url=https://your-authorised-target --reportFormat=html,xlsx
```

Only run against targets you are authorised to test.

## License

MIT — see `LICENSE`.
