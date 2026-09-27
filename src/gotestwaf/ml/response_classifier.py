"""ML-based response classifier for WAF testing.

Detects whether a response is truly blocked, passed, or a soft-block
(200 status but WAF block page). Also classifies whether a block was
from WAF rules vs bot protection.

Uses feature engineering on response characteristics + trained model.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import GridSearchCV, cross_val_score
from sklearn.preprocessing import StandardScaler


class ResponseClass(Enum):
    """Classification of a WAF response."""

    BLOCKED_BY_WAF = "blocked_by_waf"
    BLOCKED_BY_BOT_PROTECTION = "blocked_by_bot_protection"
    PASSED_NORMAL = "passed_normal"
    SOFT_BLOCKED = "soft_blocked"  # 200 status but block page content
    UNRESOLVABLE = "unresolvable"


# WAF block page signatures — trained from known WAF responses
WAF_BLOCK_SIGNATURES = [
    r"access\s*denied",
    r"forbidden",
    r"blocked",
    r"request\s*rejected",
    r"web\s*application\s*firewall",
    r"waf",
    r"security\s*violation",
    r"attack\s*detected",
    r"malicious\s*request",
    r"not\s*acceptable",
    r"error\s*1020",  # Cloudflare
    r"attention\s*required",  # Cloudflare
    r"ray\s*id",  # Cloudflare
    r"cf-chl-bypass",  # Cloudflare challenge
    r"captcha",
    r"challenge",
    r"robot",
    r"bot\s*detection",
    r"rate\s*limit",
    r"too\s*many\s*requests",
    r"incapsula",
    r"imperva",
    r"modsecurity",
    r"mod_security",
    r"akamai",
    r"cloudflare",
    r"sucuri",
    r"wordfence",
]

BOT_PROTECTION_SIGNATURES = [
    r"captcha",
    r"challenge",
    r"robot",
    r"verify\s*(you|that)\s*(are|you're)\s*(human|not\s*a\s*robot)",
    r"javascript\s*(is\s*)?required",
    r"enable\s*javascript",
    r"browser\s*check",
    r"cf-chl",
    r"__cf_chl",
    r"sgcaptcha",
    r"bot\s*protect",
    r"recaptcha",
    r"hcaptcha",
    r"turnstile",
]


@dataclass
class ResponseFeatures:
    """Feature vector extracted from an HTTP response for classification."""

    status_code: int = 0
    content_length: int = 0
    content_type_is_html: bool = False
    content_type_is_json: bool = False
    has_server_header: bool = False
    server_is_cloudflare: bool = False
    server_is_nginx: bool = False
    server_is_apache: bool = False

    # Body content features
    waf_signature_count: int = 0
    bot_signature_count: int = 0
    has_html_form: bool = False
    has_javascript: bool = False
    body_word_count: int = 0
    body_unique_word_count: int = 0
    body_entropy: float = 0.0

    # Comparison features (vs baseline)
    status_matches_baseline: bool = False
    size_ratio_to_baseline: float = 0.0
    content_similarity: float = 0.0

    def to_array(self) -> np.ndarray:
        """Convert to numpy feature array."""
        return np.array([
            self.status_code,
            self.content_length,
            int(self.content_type_is_html),
            int(self.content_type_is_json),
            int(self.has_server_header),
            int(self.server_is_cloudflare),
            int(self.server_is_nginx),
            int(self.server_is_apache),
            self.waf_signature_count,
            self.bot_signature_count,
            int(self.has_html_form),
            int(self.has_javascript),
            self.body_word_count,
            self.body_unique_word_count,
            self.body_entropy,
            int(self.status_matches_baseline),
            self.size_ratio_to_baseline,
            self.content_similarity,
        ], dtype=np.float64)

    @staticmethod
    def feature_names() -> list[str]:
        return [
            "status_code", "content_length", "content_type_html", "content_type_json",
            "has_server", "server_cloudflare", "server_nginx", "server_apache",
            "waf_signatures", "bot_signatures", "has_form", "has_javascript",
            "word_count", "unique_words", "entropy",
            "status_matches_baseline", "size_ratio", "content_similarity",
        ]


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    byte_counts = np.zeros(256, dtype=np.float64)
    for b in data:
        byte_counts[b] += 1
    probabilities = byte_counts[byte_counts > 0] / len(data)
    return float(-np.sum(probabilities * np.log2(probabilities)))


def _calculate_similarity(a: bytes, b: bytes) -> float:
    """Calculate content similarity using hash-based shingling."""
    if not a or not b:
        return 0.0

    def shingles(data: bytes, k: int = 8) -> set[bytes]:
        return {data[i:i + k] for i in range(max(1, len(data) - k + 1))}

    sa = shingles(a)
    sb = shingles(b)
    if not sa or not sb:
        return 0.0
    intersection = len(sa & sb)
    union = len(sa | sb)
    return intersection / union if union > 0 else 0.0


def extract_features(
    status_code: int,
    headers: dict[str, list[str]],
    body: bytes,
    baseline_status: int = 200,
    baseline_body: bytes = b"",
) -> ResponseFeatures:
    """Extract ML features from an HTTP response.

    Args:
        status_code: HTTP status code.
        headers: Response headers (name -> list of values).
        body: Response body bytes.
        baseline_status: Status code of baseline (normal) request.
        baseline_body: Body of baseline (normal) request.

    Returns:
        ResponseFeatures with all fields populated.
    """
    f = ResponseFeatures()
    f.status_code = status_code
    f.content_length = len(body)

    # Header features
    ct_values = headers.get("content-type", headers.get("Content-Type", []))
    ct = ct_values[0].lower() if ct_values else ""
    f.content_type_is_html = "html" in ct
    f.content_type_is_json = "json" in ct

    server_values = headers.get("server", headers.get("Server", []))
    server = server_values[0].lower() if server_values else ""
    f.has_server_header = bool(server)
    f.server_is_cloudflare = "cloudflare" in server
    f.server_is_nginx = "nginx" in server
    f.server_is_apache = "apache" in server

    # Body text features
    body_text = body.decode("utf-8", errors="replace").lower()

    f.waf_signature_count = sum(
        1 for sig in WAF_BLOCK_SIGNATURES if re.search(sig, body_text)
    )
    f.bot_signature_count = sum(
        1 for sig in BOT_PROTECTION_SIGNATURES if re.search(sig, body_text)
    )
    f.has_html_form = "<form" in body_text
    f.has_javascript = "<script" in body_text or "javascript" in body_text

    words = body_text.split()
    f.body_word_count = len(words)
    f.body_unique_word_count = len(set(words))
    f.body_entropy = _calculate_entropy(body)

    # Comparison features
    f.status_matches_baseline = status_code == baseline_status
    f.size_ratio_to_baseline = (
        len(body) / len(baseline_body) if baseline_body else 0.0
    )
    f.content_similarity = _calculate_similarity(body, baseline_body)

    return f


def classify_response_rule_based(features: ResponseFeatures) -> tuple[ResponseClass, float]:
    """Rule-based classifier as baseline / fallback.

    Returns (classification, confidence) where confidence is 0.0-1.0.
    """
    # Clear bot protection
    if features.bot_signature_count >= 2 and features.status_code in (202, 403, 429, 503):
        return ResponseClass.BLOCKED_BY_BOT_PROTECTION, 0.95

    # Clear WAF block
    if features.status_code == 403 and features.waf_signature_count >= 1:
        return ResponseClass.BLOCKED_BY_WAF, 0.95

    # Status-only WAF block (no body signatures)
    if features.status_code == 403 and features.content_length < 1000:
        return ResponseClass.BLOCKED_BY_WAF, 0.85

    # Soft block: 200 but looks like a block page
    if features.status_code == 200 and features.waf_signature_count >= 2:
        if features.size_ratio_to_baseline < 0.3:
            return ResponseClass.SOFT_BLOCKED, 0.80
        if not features.status_matches_baseline and features.content_similarity < 0.1:
            return ResponseClass.SOFT_BLOCKED, 0.70

    # Normal pass
    if features.status_code == 200 and features.waf_signature_count == 0:
        if features.content_similarity > 0.5:
            return ResponseClass.PASSED_NORMAL, 0.90
        return ResponseClass.PASSED_NORMAL, 0.70

    # Unresolvable
    return ResponseClass.UNRESOLVABLE, 0.50


class WAFResponseClassifier:
    """ML-powered response classifier with hyperparameter tuning.

    Uses a Gradient Boosting model trained on response features to classify
    WAF responses more accurately than status-code-only detection.

    Falls back to rule-based classification when not enough training data.
    """

    def __init__(self) -> None:
        self._model: GradientBoostingClassifier | None = None
        self._scaler = StandardScaler()
        self._is_trained = False
        self._training_data: list[tuple[ResponseFeatures, ResponseClass]] = []
        self._best_params: dict[str, object] = {}
        self._cv_score: float = 0.0

    def add_training_sample(self, features: ResponseFeatures, label: ResponseClass) -> None:
        """Add a labeled training sample."""
        self._training_data.append((features, label))

    def train(self, tune_hyperparameters: bool = True) -> dict[str, object]:
        """Train the model on collected samples.

        Args:
            tune_hyperparameters: If True, run GridSearchCV for optimal params.

        Returns:
            Dict with training metrics.
        """
        if len(self._training_data) < 20:
            return {"status": "insufficient_data", "samples": len(self._training_data)}

        X = np.array([f.to_array() for f, _ in self._training_data])
        y = np.array([label.value for _, label in self._training_data])

        # Scale features
        X_scaled = self._scaler.fit_transform(X)

        # Need at least 2 classes for GridSearchCV stratified splits
        if len(set(y)) < 2:
            tune_hyperparameters = False

        if tune_hyperparameters and len(self._training_data) >= 50:
            # Hyperparameter grid search
            param_grid = {
                "n_estimators": [50, 100, 200],
                "max_depth": [3, 5, 7],
                "learning_rate": [0.01, 0.1, 0.2],
                "min_samples_split": [2, 5, 10],
                "subsample": [0.8, 1.0],
            }

            base_model = GradientBoostingClassifier(random_state=42)
            cv_folds = min(5, len(set(y)))

            grid_search = GridSearchCV(
                base_model,
                param_grid,
                cv=max(2, cv_folds),
                scoring="f1_weighted",
                n_jobs=1,
                refit=True,
            )
            grid_search.fit(X_scaled, y)

            self._model = grid_search.best_estimator_
            self._best_params = grid_search.best_params_
            self._cv_score = grid_search.best_score_
        else:
            # Quick training with reasonable defaults.
            # CV-score uses a Pipeline that fits the scaler INSIDE each fold
            # so validation folds never see scaler statistics from their own
            # data — eliminates the scaler-leakage that previously inflated
            # `cv_score`. The fitted `self._scaler` is still used at inference
            # because the test/inference data isn't part of any CV fold.
            cv_folds = min(5, len(set(y)))
            if cv_folds >= 2:
                from sklearn.pipeline import Pipeline as _Pipeline
                from sklearn.preprocessing import StandardScaler as _StandardScaler
                cv_pipe = _Pipeline([
                    ("scaler", _StandardScaler()),
                    ("gb", GradientBoostingClassifier(
                        n_estimators=100, max_depth=5, learning_rate=0.1,
                        random_state=42,
                    )),
                ])
                scores = cross_val_score(cv_pipe, X, y, cv=cv_folds, scoring="f1_weighted")
                self._cv_score = float(np.mean(scores))
            else:
                self._cv_score = 0.0
            # Fit final model on full data for inference
            self._model = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                learning_rate=0.1,
                random_state=42,
            )
            self._model.fit(X_scaled, y)

        self._is_trained = True

        # Feature importance
        importance = dict(zip(
            ResponseFeatures.feature_names(),
            self._model.feature_importances_,
        ))

        return {
            "status": "trained",
            "samples": len(self._training_data),
            "cv_score": round(self._cv_score, 4),
            "best_params": self._best_params,
            "feature_importance": {k: round(v, 4) for k, v in sorted(importance.items(), key=lambda x: -x[1])[:10]},
        }

    def predict(self, features: ResponseFeatures) -> tuple[ResponseClass, float]:
        """Classify a response.

        Returns (classification, confidence).
        Uses ML model if trained, otherwise falls back to rules.
        """
        if not self._is_trained or self._model is None:
            return classify_response_rule_based(features)

        X = features.to_array().reshape(1, -1)
        X_scaled = self._scaler.transform(X)

        predicted_label = self._model.predict(X_scaled)[0]
        probabilities = self._model.predict_proba(X_scaled)[0]
        confidence = float(max(probabilities))

        return ResponseClass(predicted_label), confidence

    def auto_label_from_scan(
        self,
        status_code: int,
        headers: dict[str, list[str]],
        body: bytes,
        is_attack: bool,
        baseline_status: int = 200,
        baseline_body: bytes = b"",
    ) -> None:
        """Auto-generate training labels from scan results.

        Uses rule-based classification to bootstrap training data.
        """
        features = extract_features(status_code, headers, body, baseline_status, baseline_body)
        label, confidence = classify_response_rule_based(features)

        # Only add high-confidence auto-labels
        if confidence >= 0.80:
            self.add_training_sample(features, label)

    @property
    def training_summary(self) -> dict[str, object]:
        """Return summary of training state."""
        return {
            "is_trained": self._is_trained,
            "training_samples": len(self._training_data),
            "cv_score": self._cv_score,
            "best_params": self._best_params,
        }
