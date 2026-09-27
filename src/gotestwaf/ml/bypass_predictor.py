"""Advanced ML bypass predictor — predicts which payload mutations will evade WAF.

Uses ensemble learning with feature engineering on payload characteristics,
encoding transformations, and WAF response patterns to predict bypass probability.

Architecture:
    1. Feature extraction from payload + encoding + placement
    2. Stacked ensemble: RandomForest + GradientBoosting + neural-like MLP
    3. Bayesian hyperparameter optimization
    4. Online learning: model improves as scan progresses
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from sklearn.ensemble import (
    GradientBoostingClassifier,
    RandomForestClassifier,
    StackingClassifier,
    VotingClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler


@dataclass
class PayloadFeatureVector:
    """Rich feature representation of a payload for ML prediction."""

    # Payload content features
    payload_length: int = 0
    payload_entropy: float = 0.0
    special_char_ratio: float = 0.0
    alpha_ratio: float = 0.0
    digit_ratio: float = 0.0
    uppercase_ratio: float = 0.0
    whitespace_ratio: float = 0.0

    # Structural features
    has_html_tags: bool = False
    has_script_tag: bool = False
    has_sql_keywords: bool = False
    has_path_traversal: bool = False
    has_command_chars: bool = False
    has_url_encoding: bool = False
    has_base64_pattern: bool = False
    has_unicode_escapes: bool = False
    has_null_bytes: bool = False
    has_comment_sequences: bool = False

    # Attack type indicators
    xss_score: float = 0.0
    sqli_score: float = 0.0
    rce_score: float = 0.0
    lfi_score: float = 0.0
    xxe_score: float = 0.0
    ssti_score: float = 0.0

    # Encoding features
    encoding_type: int = 0  # 0=Plain,1=URL,2=Base64,3=JSUnicode,4=XMLEntity,5=Base64Flat
    placeholder_type: int = 0  # 0=URLParam,1=Header,2=Body,3=JSON,4=XML,5=SOAP,...

    # Evasion technique indicators
    case_mixing_score: float = 0.0
    fragmentation_score: float = 0.0
    encoding_layers: int = 0
    obfuscation_score: float = 0.0

    def to_array(self) -> np.ndarray:
        return np.array([
            self.payload_length,
            self.payload_entropy,
            self.special_char_ratio,
            self.alpha_ratio,
            self.digit_ratio,
            self.uppercase_ratio,
            self.whitespace_ratio,
            int(self.has_html_tags),
            int(self.has_script_tag),
            int(self.has_sql_keywords),
            int(self.has_path_traversal),
            int(self.has_command_chars),
            int(self.has_url_encoding),
            int(self.has_base64_pattern),
            int(self.has_unicode_escapes),
            int(self.has_null_bytes),
            int(self.has_comment_sequences),
            self.xss_score,
            self.sqli_score,
            self.rce_score,
            self.lfi_score,
            self.xxe_score,
            self.ssti_score,
            self.encoding_type,
            self.placeholder_type,
            self.case_mixing_score,
            self.fragmentation_score,
            self.encoding_layers,
            self.obfuscation_score,
        ], dtype=np.float64)

    @staticmethod
    def feature_names() -> list[str]:
        return [
            "length", "entropy", "special_ratio", "alpha_ratio", "digit_ratio",
            "upper_ratio", "space_ratio", "html_tags", "script_tag", "sql_kw",
            "path_trav", "cmd_chars", "url_enc", "b64_pattern", "unicode_esc",
            "null_bytes", "comments", "xss_score", "sqli_score", "rce_score",
            "lfi_score", "xxe_score", "ssti_score", "encoding", "placeholder",
            "case_mix", "fragment", "enc_layers", "obfuscation",
        ]


# Pattern dictionaries for attack type scoring
_XSS_PATTERNS = [
    (r"<script", 3), (r"onerror\s*=", 2), (r"onload\s*=", 2), (r"onclick\s*=", 2),
    (r"alert\s*\(", 2), (r"prompt\s*\(", 2), (r"confirm\s*\(", 2),
    (r"document\.", 2), (r"javascript:", 3), (r"<img\s", 1), (r"<svg", 1),
    (r"eval\s*\(", 2), (r"fromCharCode", 2), (r"innerHTML", 2),
]
_SQLI_PATTERNS = [
    (r"union\s+select", 3), (r"or\s+\d+=\d+", 2), (r"'\s*or\s+", 2),
    (r"information_schema", 3), (r"sleep\s*\(", 2), (r"benchmark\s*\(", 2),
    (r"waitfor\s+delay", 3), (r"--\s*$", 1), (r";\s*drop\s", 3),
    (r"exec\s*\(", 2), (r"xp_cmdshell", 3),
]
_RCE_PATTERNS = [
    (r"/etc/passwd", 3), (r"/bin/(sh|bash|cat)", 3), (r"cmd\.exe", 3),
    (r";\s*(ls|cat|id|whoami)", 2), (r"\|\s*(ls|cat|id)", 2),
    (r"`[^`]+`", 2), (r"\$\([^)]+\)", 2), (r"ping\s+", 1),
    (r"curl\s+", 1), (r"wget\s+", 1),
]
_LFI_PATTERNS = [
    (r"\.\./\.\./", 3), (r"\.\.\\\.\.\\", 3), (r"/etc/(passwd|shadow)", 3),
    (r"c:\\windows", 2), (r"file://", 2), (r"php://filter", 3),
]

_ENCODER_MAP = {"Plain": 0, "URL": 1, "Base64": 2, "JSUnicode": 3, "XMLEntity": 4, "Base64Flat": 5}
_PLACEHOLDER_MAP = {
    "URLParam": 0, "Header": 1, "RequestBody": 2, "JSONBody": 3, "JSONRequest": 4,
    "XMLBody": 5, "SOAPBody": 6, "HTMLForm": 7, "HTMLMultipartForm": 8,
    "URLPath": 9, "UserAgent": 10, "RawRequest": 11, "GraphQL": 12, "gRPC": 13,
}


def _entropy(data: str) -> float:
    if not data:
        return 0.0
    counts: dict[str, int] = {}
    for c in data:
        counts[c] = counts.get(c, 0) + 1
    probs = np.array([v / len(data) for v in counts.values()], dtype=np.float64)
    return float(-np.sum(probs * np.log2(probs)))


def _score_patterns(text: str, patterns: list[tuple[str, int]]) -> float:
    score = 0.0
    for pattern, weight in patterns:
        if re.search(pattern, text, re.I):
            score += weight
    max_possible = sum(w for _, w in patterns)
    return score / max_possible if max_possible > 0 else 0.0


def _case_mixing(text: str) -> float:
    if not text:
        return 0.0
    transitions = sum(1 for i in range(1, len(text)) if text[i].isupper() != text[i - 1].isupper() and text[i].isalpha() and text[i - 1].isalpha())
    alpha_count = sum(1 for c in text if c.isalpha())
    return transitions / alpha_count if alpha_count > 1 else 0.0


def extract_payload_features(
    payload: str,
    encoder_name: str = "Plain",
    placeholder_name: str = "URLParam",
) -> PayloadFeatureVector:
    """Extract rich features from a payload for ML prediction."""
    f = PayloadFeatureVector()

    f.payload_length = len(payload)
    f.payload_entropy = _entropy(payload)

    if payload:
        f.special_char_ratio = sum(1 for c in payload if not c.isalnum() and not c.isspace()) / len(payload)
        alpha_count = sum(1 for c in payload if c.isalpha())
        f.alpha_ratio = alpha_count / len(payload)
        f.digit_ratio = sum(1 for c in payload if c.isdigit()) / len(payload)
        # uppercase_ratio is the share of *letters* that are uppercase, not the
        # share of all characters. Using `len(payload)` as the denominator
        # silently scaled this feature inconsistently with `features.py:184`,
        # confusing the bypass predictor's scaler/model. Now matches
        # features.py exactly: uppercase_letters / max(alpha_count, 1).
        f.uppercase_ratio = (sum(1 for c in payload if c.isupper()) / max(alpha_count, 1)) if alpha_count > 0 else 0.0
        f.whitespace_ratio = sum(1 for c in payload if c.isspace()) / len(payload)

    pl = payload.lower()
    f.has_html_tags = bool(re.search(r"<[a-z]", pl))
    f.has_script_tag = "<script" in pl
    f.has_sql_keywords = bool(re.search(r"\b(select|union|insert|update|delete|drop|exec)\b", pl))
    f.has_path_traversal = "../" in payload or "..\\" in payload
    f.has_command_chars = bool(re.search(r"[;|`$]", payload))
    f.has_url_encoding = "%" in payload and bool(re.search(r"%[0-9a-fA-F]{2}", payload))
    f.has_base64_pattern = bool(re.search(r"^[A-Za-z0-9+/]{20,}={0,2}$", payload))
    f.has_unicode_escapes = "\\u" in payload
    f.has_null_bytes = "\\0" in payload or "\x00" in payload
    f.has_comment_sequences = "/*" in payload or "--" in payload or "//" in payload

    f.xss_score = _score_patterns(payload, _XSS_PATTERNS)
    f.sqli_score = _score_patterns(payload, _SQLI_PATTERNS)
    f.rce_score = _score_patterns(payload, _RCE_PATTERNS)
    f.lfi_score = _score_patterns(payload, _LFI_PATTERNS)
    f.xxe_score = 1.0 if "<!ENTITY" in payload.upper() or "SYSTEM" in payload.upper() else 0.0
    f.ssti_score = 1.0 if "{{" in payload or "{%" in payload else 0.0

    # Handle encoding chains like "URL+Base64" — use last stage for feature
    if "+" in encoder_name:
        last_stage = encoder_name.split("+")[-1].strip()
        f.encoding_type = _ENCODER_MAP.get(last_stage, 0)
    else:
        f.encoding_type = _ENCODER_MAP.get(encoder_name, 0)
    f.placeholder_type = _PLACEHOLDER_MAP.get(placeholder_name, 0)

    f.case_mixing_score = _case_mixing(payload)
    f.fragmentation_score = payload.count("<x>") / max(1, len(payload)) * 100
    f.obfuscation_score = (
        (1 if f.has_unicode_escapes else 0) +
        (1 if f.has_url_encoding else 0) +
        (1 if f.has_base64_pattern else 0) +
        (1 if f.case_mixing_score > 0.3 else 0) +
        (1 if f.fragmentation_score > 0 else 0)
    ) / 5.0

    return f


class BypassPredictor:
    """Ensemble ML model that predicts WAF bypass probability.

    Architecture:
        - Layer 1: RandomForest (captures non-linear feature interactions)
        - Layer 2: GradientBoosting (sequential error correction)
        - Layer 3: MLP (neural network for complex patterns)
        - Meta-learner: LogisticRegression (combines predictions)

    Supports online learning: model improves as scan results come in.
    """

    def __init__(self) -> None:
        self._scaler = StandardScaler()
        self._model: StackingClassifier | None = None
        self._is_trained = False
        self._samples_X: list[np.ndarray] = []
        self._samples_y: list[int] = []  # 1=bypassed, 0=blocked
        self._cv_score: float = 0.0
        self._best_threshold: float = 0.5
        # Last training-result dict, surfaced through `training_summary` for
        # downstream analyzer / report consumers. Empty dict = never trained.
        self._training_summary: dict[str, Any] = {}

    @property
    def training_summary(self) -> dict[str, Any]:
        """Most recent training-result dict (status/samples/cv_f1/etc.).

        Returns an empty dict if `train()` has not been called yet — callers
        that previously used a `hasattr` guard will keep working.
        """
        return self._training_summary

    def add_result(
        self,
        payload: str,
        encoder: str,
        placeholder: str,
        was_blocked: bool,
    ) -> None:
        """Record a scan result for online learning."""
        features = extract_payload_features(payload, encoder, placeholder)
        self._samples_X.append(features.to_array())
        self._samples_y.append(0 if was_blocked else 1)

    def train(self) -> dict[str, Any]:
        """Train the stacking ensemble with hyperparameter optimization.

        Returns training metrics.
        """
        n = len(self._samples_X)
        if n < 30:
            self._training_summary = {"status": "insufficient_data", "samples": n, "min_required": 30}
            return self._training_summary

        X = np.array(self._samples_X)
        y = np.array(self._samples_y)

        # Handle class imbalance
        n_positive = sum(y)
        n_negative = n - n_positive
        if n_positive == 0 or n_negative == 0:
            self._training_summary = {"status": "single_class", "samples": n, "bypassed": int(n_positive), "blocked": int(n_negative)}
            return self._training_summary

        X_scaled = self._scaler.fit_transform(X)

        # Build stacking ensemble
        # MLP: disable early_stopping when minority class < 10 samples
        use_early_stop = min(n_positive, n_negative) >= 10
        mlp_kw = {"hidden_layer_sizes": (64, 32, 16), "activation": "relu",
                   "max_iter": 500, "random_state": 42}
        if use_early_stop:
            mlp_kw["early_stopping"] = True
            mlp_kw["validation_fraction"] = 0.15

        estimators = [
            ("rf", RandomForestClassifier(
                n_estimators=100, max_depth=7, min_samples_split=5,
                class_weight="balanced", random_state=42, n_jobs=1,
            )),
            ("gb", GradientBoostingClassifier(
                n_estimators=100, max_depth=5, learning_rate=0.1,
                subsample=0.8, random_state=42,
            )),
            ("mlp", MLPClassifier(**mlp_kw)),
        ]

        self._model = StackingClassifier(
            estimators=estimators,
            final_estimator=LogisticRegression(
                C=1.0, class_weight="balanced", max_iter=1000, random_state=42,
            ),
            cv=max(2, min(5, n_positive, n_negative)),
            stack_method="predict_proba",
            n_jobs=1,
        )

        # Cross-validation with Pipeline-wrapped clone — each fold fits its
        # own scaler so scaler statistics from the full dataset never leak
        # into the validation folds. (Passing `X_scaled` directly leaked the
        # global scaler's mean/std and inflated cv_f1.)
        cv_folds = min(5, n_positive, n_negative)
        if cv_folds >= 2:
            from sklearn.base import clone
            from sklearn.model_selection import StratifiedKFold, cross_val_predict
            from sklearn.pipeline import Pipeline as _Pipeline
            from sklearn.preprocessing import StandardScaler as _StdScaler
            cv_pipeline = _Pipeline([
                ("scaler", _StdScaler()),
                ("model", clone(self._model)),
            ])
            scores = cross_val_score(cv_pipeline, X, y, cv=cv_folds, scoring="f1")
            self._cv_score = float(np.mean(scores))

        self._model.fit(X_scaled, y)

        # Find optimal threshold using OUT-OF-FOLD predictions (no label leakage).
        # Computing the threshold on `predict_proba(X_scaled)` after `fit(X_scaled)`
        # uses each sample's prediction from a model that has seen it during
        # training — the resulting threshold is over-fitted and generalizes
        # poorly to unseen payloads. cross_val_predict gives each sample a
        # prediction from a fold where it was held out.
        threshold_set = False
        if cv_folds >= 2:
            try:
                from sklearn.base import clone as _clone
                from sklearn.model_selection import StratifiedKFold as _SKF, cross_val_predict as _cvp
                oof_proba = _cvp(
                    _clone(self._model), X_scaled, y,
                    cv=_SKF(n_splits=cv_folds, shuffle=True, random_state=42),
                    method="predict_proba",
                    n_jobs=1,
                )[:, 1]
                best_f1 = 0.0
                for threshold in np.arange(0.3, 0.8, 0.05):
                    preds = (oof_proba >= threshold).astype(int)
                    tp = int(np.sum((preds == 1) & (y == 1)))
                    fp = int(np.sum((preds == 1) & (y == 0)))
                    fn = int(np.sum((preds == 0) & (y == 1)))
                    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
                    if f1 > best_f1:
                        best_f1 = f1
                        self._best_threshold = float(threshold)
                threshold_set = True
            except Exception:
                pass  # fall through to in-sample fallback
        if not threshold_set:
            # Fallback when CV-predict is unavailable (very small data) — keep
            # the previous in-sample threshold-search behavior.
            probas = self._model.predict_proba(X_scaled)[:, 1]
            best_f1 = 0.0
            for threshold in np.arange(0.3, 0.8, 0.05):
                preds = (probas >= threshold).astype(int)
                tp = int(np.sum((preds == 1) & (y == 1)))
                fp = int(np.sum((preds == 1) & (y == 0)))
                fn = int(np.sum((preds == 0) & (y == 1)))
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
                if f1 > best_f1:
                    best_f1 = f1
                    self._best_threshold = float(threshold)

        self._is_trained = True

        # Feature importance from RF component
        rf_model = self._model.estimators_[0]
        importance = dict(zip(
            PayloadFeatureVector.feature_names(),
            rf_model.feature_importances_,
        ))

        self._training_summary = {
            "status": "trained",
            "samples": n,
            "bypassed": int(n_positive),
            "blocked": int(n_negative),
            "cv_f1_score": round(self._cv_score, 4),
            "optimal_threshold": round(self._best_threshold, 4),
            "feature_importance": {
                k: round(float(v), 4)
                for k, v in sorted(importance.items(), key=lambda x: -x[1])[:10]
            },
        }
        return self._training_summary

    def predict_bypass_probability(
        self,
        payload: str,
        encoder: str = "Plain",
        placeholder: str = "URLParam",
    ) -> dict[str, Any]:
        """Predict probability that a payload will bypass the WAF.

        Returns dict with probability, confidence, and contributing factors.
        """
        features = extract_payload_features(payload, encoder, placeholder)

        if not self._is_trained or self._model is None:
            # Fall back to heuristic scoring
            heuristic_score = (
                features.obfuscation_score * 0.3 +
                (1.0 if features.encoding_type > 0 else 0.0) * 0.2 +
                (1.0 if features.placeholder_type >= 8 else 0.0) * 0.2 +
                features.case_mixing_score * 0.15 +
                features.fragmentation_score * 0.15
            )
            return {
                "bypass_probability": round(float(heuristic_score), 4),
                "confidence": 0.3,
                "method": "heuristic",
                "payload_type": _dominant_attack_type(features),
                "evasion_techniques": _detect_evasion_techniques(features),
            }

        X = features.to_array().reshape(1, -1)
        X_scaled = self._scaler.transform(X)
        proba_arr = self._model.predict_proba(X_scaled)[0]
        proba = float(proba_arr[1]) if len(proba_arr) > 1 else float(proba_arr[0])

        # Get individual estimator predictions for confidence
        model_names = ["random_forest", "gradient_boosting", "neural_network"]
        individual_preds = []
        for est in self._model.estimators_:
            try:
                p = est.predict_proba(X_scaled)[0]
                individual_preds.append(float(p[1]) if len(p) > 1 else float(p[0]))
            except Exception:
                individual_preds.append(0.5)
        agreement = 1.0 - float(np.std(individual_preds)) if individual_preds else 0.5

        individual_results = {}
        for idx, name in enumerate(model_names):
            if idx < len(individual_preds):
                individual_results[name] = round(individual_preds[idx], 4)

        return {
            "bypass_probability": round(proba, 4),
            "will_bypass": proba >= self._best_threshold,
            "confidence": round(agreement, 4),
            "method": "ensemble_ml",
            "threshold": self._best_threshold,
            "payload_type": _dominant_attack_type(features),
            "evasion_techniques": _detect_evasion_techniques(features),
            "individual_models": individual_results,
        }

    def suggest_mutations(
        self,
        payload: str,
        encoder: str = "Plain",
        placeholder: str = "URLParam",
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Suggest payload mutations most likely to bypass the WAF.

        Returns ranked list of mutation suggestions with predicted bypass probability.
        """
        mutations: list[dict[str, Any]] = []

        # Try different encoders
        for enc in ["Plain", "URL", "Base64", "Base64Flat", "JSUnicode", "XMLEntity"]:
            if enc != encoder:
                pred = self.predict_bypass_probability(payload, enc, placeholder)
                mutations.append({
                    "mutation": f"Re-encode with {enc}",
                    "encoder": enc,
                    "placeholder": placeholder,
                    "payload": payload,
                    "bypass_probability": pred["bypass_probability"],
                })

        # Try different placements
        for ph in ["URLParam", "Header", "UserAgent", "JSONBody", "RawRequest", "URLPath"]:
            if ph != placeholder:
                pred = self.predict_bypass_probability(payload, encoder, ph)
                mutations.append({
                    "mutation": f"Place in {ph}",
                    "encoder": encoder,
                    "placeholder": ph,
                    "payload": payload,
                    "bypass_probability": pred["bypass_probability"],
                })

        # Try payload mutations
        payload_mutations = [
            (payload.replace("<", "<x>").replace(">", "<x>"), "Tag fragmentation"),
            (payload.swapcase(), "Case swap"),
            (payload.replace(" ", "/**/"), "Comment insertion"),
            (payload + "\x00", "Null byte append"),
            (payload.replace("'", "%27"), "Manual URL encode quotes"),
        ]
        for mutated, desc in payload_mutations:
            pred = self.predict_bypass_probability(mutated, encoder, placeholder)
            mutations.append({
                "mutation": desc,
                "encoder": encoder,
                "placeholder": placeholder,
                "payload": mutated,
                "bypass_probability": pred["bypass_probability"],
            })

        mutations.sort(key=lambda x: x["bypass_probability"], reverse=True)
        return mutations[:top_k]


def _dominant_attack_type(f: PayloadFeatureVector) -> str:
    scores = {
        "xss": f.xss_score,
        "sqli": f.sqli_score,
        "rce": f.rce_score,
        "lfi": f.lfi_score,
        "xxe": f.xxe_score,
        "ssti": f.ssti_score,
    }
    if max(scores.values()) == 0:
        return "unknown"
    return max(scores, key=scores.get)


def _detect_evasion_techniques(f: PayloadFeatureVector) -> list[str]:
    techniques = []
    if f.has_unicode_escapes:
        techniques.append("unicode_escape")
    if f.has_url_encoding:
        techniques.append("url_encoding")
    if f.has_base64_pattern:
        techniques.append("base64_encoding")
    if f.case_mixing_score > 0.3:
        techniques.append("case_mixing")
    if f.fragmentation_score > 0:
        techniques.append("tag_fragmentation")
    if f.has_null_bytes:
        techniques.append("null_byte_injection")
    if f.has_comment_sequences:
        techniques.append("comment_insertion")
    if f.encoding_type > 0:
        techniques.append(f"encoding_{['plain','url','b64','jsunicode','xmlentity','b64flat'][f.encoding_type]}")
    return techniques
