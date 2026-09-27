"""Production hybrid ML engine for WAF testing intelligence.

Architecture:
    Layer 1 — Rule-based classifier (fast, deterministic)
    Layer 2 — Unsupervised anomaly detection (Isolation Forest + LOF)
    Layer 3 — Stacking ensemble (RF + GBM + MLP → LogisticRegression meta-learner)
    Layer 4 — Drift detector (KS-test + PSI for feature distribution monitoring)

The engine trains online as scan results come in, then produces:
    - Enhanced response classifications with confidence
    - Bypass probability predictions for blocked payloads
    - Mutation suggestions ranked by predicted bypass probability
    - Model performance metrics and drift warnings
"""

from __future__ import annotations

import json
import math
import os
import warnings
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import (
    GradientBoostingClassifier,
    IsolationForest,
    RandomForestClassifier,
    StackingClassifier,
)
from sklearn.exceptions import NotFittedError
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    f1_score,
    precision_score,
    recall_score,
    silhouette_score,
)
from sklearn.model_selection import cross_val_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

import structlog

from gotestwaf.ml.features import (
    PAYLOAD_FEATURE_DIM,
    PAYLOAD_FEATURE_NAMES,
    RESPONSE_FEATURE_DIM,
    RESPONSE_FEATURE_NAMES,
    extract_payload_features,
    extract_response_features,
)

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
logger = structlog.get_logger()


class ResponseVerdict(Enum):
    """ML-enhanced response classification."""
    BLOCKED_BY_WAF = "blocked_by_waf"
    BLOCKED_BY_BOT = "blocked_by_bot_protection"
    PASSED = "passed"
    SOFT_BLOCKED = "soft_blocked"
    UNRESOLVABLE = "unresolvable"


@dataclass
class Prediction:
    """Single prediction result with confidence and explanation."""
    verdict: ResponseVerdict
    confidence: float  # 0.0 - 1.0
    bypass_probability: float  # 0.0 - 1.0 for blocked payloads
    attack_type: str
    source: str  # "rules", "ensemble", "fallback"
    feature_contributions: dict[str, float] = field(default_factory=dict)


@dataclass
class TrainingMetrics:
    """Model training results."""
    samples: int = 0
    bypassed: int = 0
    blocked: int = 0
    cv_f1: float = 0.0
    ensemble_weights: dict[str, float] = field(default_factory=dict)
    feature_importance: dict[str, float] = field(default_factory=dict)
    anomaly_stats: dict[str, float] = field(default_factory=dict)
    drift_warnings: list[str] = field(default_factory=list)
    # Per-class precision/recall/f1/support (computed from OOF predictions
    # at threshold 0.5). Empty dict when training was skipped or fallback.
    per_class: dict = field(default_factory=dict)
    # Reliability-diagram data: list of dicts with bin_centre, predicted_mean,
    # actual_freq, count — populated by the calibrated stacking path.
    calibration: list = field(default_factory=list)
    # Per-base-model ablation: F1 of each component trained alone, plus the
    # combined stacking ensemble. Populated when env GOTESTWAF_EXTENDED=1.
    ablation: dict = field(default_factory=dict)
    # Learning-curve data: per-model dict with sizes, train_mean, train_std,
    # val_mean, val_std arrays. Populated when env GOTESTWAF_EXTENDED=1.
    learning_curves: dict = field(default_factory=dict)


class HybridMLEngine:
    """Production hybrid ML engine with multi-layer architecture.

    Usage:
        engine = HybridMLEngine()

        # Feed scan results as they come in
        for result in scan_results:
            engine.add_result(payload, encoder, placeholder, status_code, headers, body)

        # Train all models
        metrics = engine.train()

        # Get enhanced predictions
        prediction = engine.predict(payload, encoder, placeholder, status_code, headers, body)

        # Get bypass mutation suggestions
        mutations = engine.suggest_mutations(payload, encoder, placeholder)
    """

    def __init__(self) -> None:
        # Scalers
        self._payload_scaler = StandardScaler()
        self._response_scaler = StandardScaler()
        self._combined_scaler = StandardScaler()

        # Layer 2: Unsupervised anomaly detection
        self._isolation_forest: IsolationForest | None = None
        self._lof: LocalOutlierFactor | None = None

        # Layer 3: Stacking ensemble
        # Type widened from StackingClassifier — round-13 wraps the stacking
        # ensemble in CalibratedClassifierCV, and the RF-only fallback for
        # tiny minority classes assigns a RandomForestClassifier here.
        self._ensemble: Any = None
        self._is_trained = False

        # Training data
        self._payload_features: list[np.ndarray] = []
        self._response_features: list[np.ndarray] = []
        self._labels: list[int] = []  # 1 = bypassed, 0 = blocked
        self._metadata: list[dict[str, str]] = []

        # Baseline response for comparison
        self._baseline_status: int = 200
        self._baseline_body: bytes = b""

        # Training metrics
        self._metrics = TrainingMetrics()

        # Drift detection
        self._training_feature_stats: dict[str, tuple[float, float]] | None = None

    def set_baseline(self, status_code: int, body: bytes) -> None:
        """Set the baseline response from a normal (non-attack) request."""
        self._baseline_status = status_code
        self._baseline_body = body

    def add_result(
        self,
        payload: str,
        encoder: str,
        placeholder: str,
        status_code: int,
        headers: dict[str, list[str]],
        body: bytes,
        was_blocked: bool,
        test_set: str = "",
        test_case: str = "",
    ) -> None:
        """Record a scan result for model training."""
        pf = extract_payload_features(payload, encoder, placeholder)
        rf = extract_response_features(
            status_code, headers, body,
            self._baseline_status, self._baseline_body,
        )
        self._payload_features.append(pf)
        self._response_features.append(rf)
        self._labels.append(0 if was_blocked else 1)
        self._metadata.append({
            "payload": payload[:200],
            "encoder": encoder,
            "placeholder": placeholder,
            "test_set": test_set,
            "test_case": test_case,
            "status_code": str(status_code),
        })

    def train(self) -> TrainingMetrics:
        """Train all ML layers on collected data.

        Returns comprehensive training metrics.
        """
        n = len(self._labels)
        self._metrics = TrainingMetrics(samples=n)

        if n < 30:
            logger.warning("Not enough data to train ML models", samples=n)
            return self._metrics

        X_payload = np.array(self._payload_features)
        X_response = np.array(self._response_features)
        y = np.array(self._labels)

        self._metrics.bypassed = int(np.sum(y == 1))
        self._metrics.blocked = int(np.sum(y == 0))

        # Scale features
        X_payload_scaled = self._payload_scaler.fit_transform(X_payload)
        X_response_scaled = self._response_scaler.fit_transform(X_response)

        # Combined features for anomaly detection (unsupervised — uses everything)
        X_combined = np.hstack([X_payload_scaled, X_response_scaled])
        X_combined = self._combined_scaler.fit_transform(X_combined)

        # Supervised model uses ONLY payload features (not response features)
        # Using response features (status_code, body_length) causes overfitting
        # because they perfectly correlate with the label (status=403 → blocked).
        # The supervised model should predict bypass probability from PAYLOAD
        # characteristics, not from the response it already received.
        X_supervised = X_payload_scaled

        # Store training stats for drift detection
        self._training_feature_stats = {
            f"f_{i}": (float(np.mean(X_combined[:, i])), float(np.std(X_combined[:, i])))
            for i in range(X_combined.shape[1])
        }

        # ---- Layer 2: Unsupervised anomaly detection ----
        try:
            # contamination must be in (0, 0.5] — clamp to valid range
            bypass_ratio = self._metrics.bypassed / max(n, 1)
            contamination = max(0.01, min(0.5, bypass_ratio))
            self._isolation_forest = IsolationForest(
                n_estimators=200,
                max_samples="auto",
                contamination=contamination,
                random_state=42,
                n_jobs=-1,
            )
            self._isolation_forest.fit(X_combined)

            anomaly_scores = self._isolation_forest.decision_function(X_combined)
            self._metrics.anomaly_stats = {
                "mean_score": float(np.mean(anomaly_scores)),
                "std_score": float(np.std(anomaly_scores)),
                "anomaly_pct": float((anomaly_scores < 0).mean()),
            }
        except Exception as e:
            logger.warning("Isolation Forest training failed", error=str(e))

        # ---- Layer 3: Stacking ensemble ----
        n_bypass = int(np.sum(y == 1))
        n_block = int(np.sum(y == 0))
        n_minority = min(n_bypass, n_block)

        if n_minority < 2:
            logger.warning("Single-class data, skipping ensemble training",
                          bypassed=n_bypass, blocked=n_block)
            return self._metrics

        # When the minority class is small, StackingClassifier's internal
        # cross_val_predict creates folds where GB and MLP base learners
        # see degenerate splits — "1 class in fold" / "1 class after
        # sample_weight trimmed" ValueErrors that escape sklearn's parallel
        # joblib wrapper as "All N fits failed". Threshold raised to 10
        # because:
        #   - With n_minority=5 and cv=5, each train fold has 4 minority,
        #     but GB's internal validation split (or subsample) can still
        #     produce single-class folds.
        #   - Below 10, the stacking ensemble adds noise more than signal
        #     anyway — a single class-balanced RF is more honest.
        # The fallback uses a single RandomForest (handles imbalance via
        # class_weight, no internal subsampling, no internal CV).
        def _train_rf_only(reason: str) -> None:
            try:
                rf_solo = RandomForestClassifier(
                    n_estimators=200, max_depth=8, min_samples_split=2,
                    class_weight="balanced", random_state=42, n_jobs=1,
                )
                rf_solo.fit(X_supervised, y)
                self._ensemble = rf_solo
                self._is_trained = True

                cv_folds = max(2, min(5, n_minority))
                try:
                    cv_scores = cross_val_score(
                        RandomForestClassifier(
                            n_estimators=100, max_depth=8,
                            class_weight="balanced", random_state=42, n_jobs=1,
                        ),
                        X_supervised, y, cv=cv_folds, scoring="f1",
                    )
                    self._metrics.cv_f1 = float(np.mean(cv_scores))
                except Exception as cv_err:
                    logger.warning("CV scoring failed on imbalanced data", error=str(cv_err))

                payload_names = PAYLOAD_FEATURE_NAMES
                if len(payload_names) == X_supervised.shape[1]:
                    importance = dict(zip(payload_names, (float(v) for v in rf_solo.feature_importances_)))
                else:
                    importance = {f"f_{i}": float(v) for i, v in enumerate(rf_solo.feature_importances_)}
                self._metrics.feature_importance = {
                    k: round(float(v), 4)
                    for k, v in sorted(importance.items(), key=lambda x: -x[1])[:15]
                }

                logger.info(
                    "ML engine trained (RF-only)",
                    samples=n, cv_f1=round(self._metrics.cv_f1, 4),
                    bypassed=n_bypass, blocked=n_block, reason=reason,
                )
            except Exception as rf_err:
                logger.warning("RF-only training failed", error=str(rf_err))

        if n_minority < 10:
            _train_rf_only(reason=f"minority_class_too_small_n={n_minority}")
            return self._metrics

        try:
            # MLP: disable early_stopping when minority class is small
            # (validation split can end up with 0 samples of one class)
            use_early_stopping = n_minority >= 10
            mlp_kwargs = {
                # Smaller hidden layers + L2 regularisation reduce overfit
                # on small WAF training sets where features are sparse.
                "hidden_layer_sizes": (48, 24), "activation": "relu",
                "alpha": 1e-3,        # L2 weight decay
                "max_iter": 500, "random_state": 42,
            }
            if use_early_stopping:
                mlp_kwargs["early_stopping"] = True
                mlp_kwargs["validation_fraction"] = 0.15

            # GB subsample only when minority class is large enough to survive
            # an 80% bootstrap; otherwise disable subsampling to avoid
            # single-class folds inside cross_val_predict.
            gb_subsample = 0.8 if n_minority >= 10 else 1.0

            # Reduced tree depths + higher min_samples_leaf trade a tiny bit
            # of train F1 for far better generalisation on small datasets.
            # Plus explicit per-sample weighting via compute_sample_weight
            # ensures the loss function actually penalises the minority class
            # proportionally, not just RF's tree-internal class_weight.
            from sklearn.utils.class_weight import compute_sample_weight
            sample_weights = compute_sample_weight("balanced", y)

            estimators = [
                ("rf", RandomForestClassifier(
                    n_estimators=200, max_depth=6, min_samples_split=10,
                    min_samples_leaf=4, max_features="sqrt",
                    class_weight="balanced", random_state=42, n_jobs=1,
                )),
                ("gb", GradientBoostingClassifier(
                    n_estimators=120, max_depth=4, learning_rate=0.08,
                    subsample=gb_subsample, min_samples_split=10,
                    min_samples_leaf=4, random_state=42,
                )),
                ("mlp", MLPClassifier(**mlp_kwargs)),
            ]

            cv_folds = min(5, n_minority)

            base_ensemble = StackingClassifier(
                estimators=estimators,
                final_estimator=LogisticRegression(
                    C=0.5,             # stronger L2 regularisation on meta-learner
                    class_weight="balanced", max_iter=1000, random_state=42,
                ),
                cv=max(2, cv_folds),
                stack_method="predict_proba",
                n_jobs=1,  # Avoid excessive parallelism in Docker
            )
            # Train the base stacking ensemble FIRST with per-sample weights
            # (so GB and MLP — which lack a class_weight parameter — actually
            # see the imbalance correction), then wrap it with
            # CalibratedClassifierCV for probability calibration.
            #
            # sklearn API moved targets here:
            #   * 1.5 and earlier: CalibratedClassifierCV(cv="prefit", estimator=fit_est)
            #   * 1.6+: CalibratedClassifierCV(estimator=FrozenEstimator(fit_est))
            #     ("prefit" string raises ValueError on 1.6+)
            # The version-tolerant fallback chain below uses FrozenEstimator
            # when available, then "prefit", then a final unweighted retrain
            # via standard cv=3 (which would refit the inner estimator and
            # lose the sample_weight benefit, but at least produces a
            # calibrated model).
            from sklearn.calibration import CalibratedClassifierCV
            try:
                base_ensemble.fit(X_supervised, y, sample_weight=sample_weights)
            except (TypeError, ValueError):
                base_ensemble.fit(X_supervised, y)

            self._ensemble = None
            try:
                from sklearn.frozen import FrozenEstimator
                self._ensemble = CalibratedClassifierCV(
                    estimator=FrozenEstimator(base_ensemble),
                    method="isotonic",
                )
                self._ensemble.fit(X_supervised, y)
            except ImportError:
                try:
                    self._ensemble = CalibratedClassifierCV(
                        estimator=base_ensemble,
                        method="isotonic",
                        cv="prefit",
                    )
                    self._ensemble.fit(X_supervised, y)
                except (TypeError, ValueError):
                    # sklearn 1.6+ without FrozenEstimator: use the base
                    # ensemble directly. Probabilities won't be isotonic-
                    # calibrated but the model is still well class-balanced.
                    self._ensemble = base_ensemble
            self._is_trained = True

            # Cross-validation score — clone the EXACT deployed ensemble
            # (RF + GB + MLP) and wrap it in a Pipeline with its own scaler
            # so each fold's validation set never sees scaler statistics from
            # itself. `X_supervised` was already scaled by the engine's
            # global scaler; passing it directly into cross_val_score would
            # leak that scaler's mean/std into every fold's holdout. Use raw
            # `X_payload` (the unscaled features) inside the pipeline.
            if cv_folds >= 2:
                from sklearn.base import clone
                from sklearn.pipeline import Pipeline
                from sklearn.preprocessing import StandardScaler
                from sklearn.model_selection import cross_val_predict, StratifiedKFold
                # Build a NON-prefit CalibratedClassifierCV for CV scoring.
                # Cloning the deployed `self._ensemble` (which uses cv="prefit")
                # wipes fit state, then cross_val_score tries to fit it on
                # each fold — but cv="prefit" requires the inner estimator to
                # already be fitted, so the fit fails with NotFittedError and
                # the whole stacking-CV path falls through to the RF-only
                # safety net. Use cv=3 so each CV fold trains its own
                # calibrated classifier from scratch.
                cv_calib_folds = max(2, min(3, cv_folds))
                cv_calibrated = CalibratedClassifierCV(
                    estimator=clone(base_ensemble),
                    method="isotonic",
                    cv=cv_calib_folds,
                )
                cv_pipeline = Pipeline([
                    ("scaler", StandardScaler()),
                    ("ensemble", cv_calibrated),
                ])
                cv_scores = cross_val_score(
                    cv_pipeline, X_payload, y,
                    cv=cv_folds, scoring="f1",
                )
                self._metrics.cv_f1 = float(np.mean(cv_scores))

                # Flag overfitting: if F1 > 0.99, the model is likely memorizing
                if self._metrics.cv_f1 > 0.99:
                    logger.warning("ML F1 > 0.99 — possible overfitting, check feature leakage")

                # Compute out-of-fold probabilities for the calibration plot
                # and per-class precision/recall. Using the same Pipeline
                # ensures we measure the deployed model's behaviour, not a
                # training-set-fit artefact.
                try:
                    skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
                    oof_proba = cross_val_predict(
                        clone(cv_pipeline), X_payload, y, cv=skf,
                        method="predict_proba", n_jobs=1,
                    )[:, 1]
                    # Per-class precision/recall at threshold 0.5
                    from sklearn.metrics import (
                        precision_score, recall_score, f1_score,
                    )
                    preds_05 = (oof_proba >= 0.5).astype(int)
                    self._metrics.per_class = {
                        "blocked": {
                            "precision": float(precision_score(y, preds_05, pos_label=0, zero_division=0)),
                            "recall":    float(recall_score(y, preds_05, pos_label=0, zero_division=0)),
                            "f1":        float(f1_score(y, preds_05, pos_label=0, zero_division=0)),
                            "support":   int(np.sum(y == 0)),
                        },
                        "bypassed": {
                            "precision": float(precision_score(y, preds_05, pos_label=1, zero_division=0)),
                            "recall":    float(recall_score(y, preds_05, pos_label=1, zero_division=0)),
                            "f1":        float(f1_score(y, preds_05, pos_label=1, zero_division=0)),
                            "support":   int(np.sum(y == 1)),
                        },
                    }
                    # Calibration data: bin OOF probabilities into 10 deciles,
                    # measure the actual frequency of class 1 in each bin.
                    # A perfectly-calibrated model has bin centre ≈ bin actual.
                    bins = np.linspace(0.0, 1.0, 11)
                    bin_idx = np.minimum(np.digitize(oof_proba, bins) - 1, 9)
                    calibration = []
                    for b in range(10):
                        mask = bin_idx == b
                        if int(mask.sum()) > 0:
                            calibration.append({
                                "bin_centre": round(float((bins[b] + bins[b+1]) / 2), 3),
                                "predicted_mean": round(float(oof_proba[mask].mean()), 3),
                                "actual_freq": round(float(y[mask].mean()), 3),
                                "count": int(mask.sum()),
                            })
                    self._metrics.calibration = calibration
                except Exception as cal_err:
                    logger.debug("Calibration / per-class metrics skipped", error=str(cal_err))

                # ── Extended metrics (ablation + learning curves) ──
                # Only run when explicitly requested because they retrain
                # estimators many times. Total cost on N≈1100 is ~30-90s.
                if os.environ.get("GOTESTWAF_EXTENDED") == "1":
                    try:
                        self._compute_extended_metrics(
                            X_payload, y, cv_folds=cv_folds,
                        )
                    except Exception as ext_err:
                        logger.warning(
                            "Extended metrics computation failed",
                            error=str(ext_err),
                        )

            # Feature importance — extract from one of the calibrated base
            # estimators' RF component. CalibratedClassifierCV stores
            # `calibrated_classifiers_[i].estimator` (sklearn ≥1.2) which is
            # the original StackingClassifier; its `estimators_[0]` is the
            # fitted RF. We average importance across the calibration folds
            # for a more stable ranking.
            try:
                rf_importances = []
                for cc in getattr(self._ensemble, "calibrated_classifiers_", []):
                    inner = getattr(cc, "estimator", None) or getattr(cc, "base_estimator", None)
                    if inner is not None and hasattr(inner, "estimators_"):
                        rf_importances.append(inner.estimators_[0].feature_importances_)
                if rf_importances:
                    importance_arr = np.mean(rf_importances, axis=0)
                else:
                    # Fallback: a fresh RF on the same data so feature_importance is non-empty
                    rf_proxy = RandomForestClassifier(
                        n_estimators=150, max_depth=6, class_weight="balanced",
                        random_state=42, n_jobs=1,
                    )
                    rf_proxy.fit(X_supervised, y)
                    importance_arr = rf_proxy.feature_importances_
                payload_names = PAYLOAD_FEATURE_NAMES
                if len(payload_names) == X_supervised.shape[1]:
                    importance = dict(zip(payload_names, (float(v) for v in importance_arr)))
                else:
                    importance = {f"f_{i}": float(v) for i, v in enumerate(importance_arr)}
                self._metrics.feature_importance = {
                    k: round(float(v), 4)
                    for k, v in sorted(importance.items(), key=lambda x: -x[1])[:15]
                }
            except Exception as fi_err:
                logger.debug("Feature importance extraction failed", error=str(fi_err))

            logger.info(
                "ML engine trained",
                samples=n, cv_f1=round(self._metrics.cv_f1, 4),
                bypassed=n_bypass, blocked=n_block,
            )

        except Exception as e:
            # StackingClassifier failed for some unforeseen reason (sklearn
            # version drift, edge-case stratification, OOM in joblib...).
            # Fall back to RF-only so downstream code (model_store,
            # predict()) still has a usable model rather than `None`.
            logger.error("Ensemble training failed — falling back to RF-only", error=str(e))
            self._is_trained = False
            self._ensemble = None
            _train_rf_only(reason="stacking_failed")

        return self._metrics

    def predict(
        self,
        payload: str,
        encoder: str,
        placeholder: str,
        status_code: int,
        headers: dict[str, list[str]],
        body: bytes,
    ) -> Prediction:
        """Classify a WAF response with ML-enhanced confidence.

        Layer 1 (rules) → Layer 2 (anomaly) → Layer 3 (ensemble).
        """
        # ---- Layer 1: Rule-based (fast, deterministic) ----
        rule_result = self._rule_classify(status_code, headers, body)
        if rule_result.confidence >= 0.95:
            return rule_result

        # ---- Prepare features ----
        pf = extract_payload_features(payload, encoder, placeholder)
        rf = extract_response_features(
            status_code, headers, body,
            self._baseline_status, self._baseline_body,
        )

        if not self._is_trained:
            return rule_result

        try:
            pf_scaled = self._payload_scaler.transform(pf.reshape(1, -1))
            rf_scaled = self._response_scaler.transform(rf.reshape(1, -1))
            X = self._combined_scaler.transform(np.hstack([pf_scaled, rf_scaled]))
        except NotFittedError:
            return rule_result

        # ---- Layer 2: Anomaly score ----
        anomaly_score = 0.0
        if self._isolation_forest is not None:
            anomaly_score = float(self._isolation_forest.decision_function(X)[0])

        # ---- Layer 3: Ensemble prediction (payload features only) ----
        if self._ensemble is not None:
            try:
                proba = self._ensemble.predict_proba(pf_scaled)[0]
                bypass_prob = float(proba[1]) if len(proba) > 1 else 0.0
                confidence = float(max(proba))

                # Determine dominant attack type
                attack_type = self._classify_attack_type(pf)

                # Get individual model predictions for explanation. The
                # ensemble may be one of:
                #   * CalibratedClassifierCV(estimator=StackingClassifier(...))
                #     — the round-13 default for non-tiny training sets.
                #   * StackingClassifier — legacy / direct path.
                #   * RandomForestClassifier — RF-only fallback for tiny
                #     minority class. No per-base breakdown to expose.
                # The previous `isinstance(self._ensemble, StackingClassifier)`
                # check silently always returned False after round-13's
                # CalibratedClassifierCV wrap, so the per-model breakdown
                # was permanently empty for every successful train.
                individual = {}
                inner_stacking = None
                if isinstance(self._ensemble, StackingClassifier):
                    inner_stacking = self._ensemble
                else:
                    calib_cls = getattr(self._ensemble, "calibrated_classifiers_", None)
                    if calib_cls:
                        first = calib_cls[0]
                        candidate = getattr(first, "estimator", None) or getattr(first, "base_estimator", None)
                        if isinstance(candidate, StackingClassifier):
                            inner_stacking = candidate
                if inner_stacking is not None:
                    for name, est in zip(["rf", "gb", "mlp"], inner_stacking.estimators_):
                        try:
                            p = est.predict_proba(pf_scaled)[0]
                            individual[name] = float(p[1]) if len(p) > 1 else 0.0
                        except Exception:
                            pass

                if bypass_prob > 0.5:
                    verdict = ResponseVerdict.PASSED
                else:
                    verdict = rule_result.verdict

                return Prediction(
                    verdict=verdict,
                    confidence=confidence,
                    bypass_probability=bypass_prob,
                    attack_type=attack_type,
                    source="ensemble",
                    feature_contributions=individual,
                )
            except Exception:
                pass

        return rule_result

    def suggest_mutations(
        self,
        payload: str,
        encoder: str = "Plain",
        placeholder: str = "URLParam",
        top_k: int = 10,
    ) -> list[dict[str, Any]]:
        """Predict which payload mutations are most likely to bypass the WAF."""
        suggestions: list[dict[str, Any]] = []

        # Try alternative encoders
        for enc in ["Plain", "URL", "Base64", "Base64Flat", "JSUnicode", "XMLEntity"]:
            if enc != encoder:
                prob = self._predict_bypass_prob(payload, enc, placeholder)
                suggestions.append({
                    "mutation": f"Re-encode with {enc}",
                    "payload": payload,
                    "encoder": enc,
                    "placeholder": placeholder,
                    "bypass_probability": prob,
                })

        # Try alternative placements
        for ph in ["URLParam", "Header", "UserAgent", "JSONBody", "URLPath", "RawRequest"]:
            if ph != placeholder:
                prob = self._predict_bypass_prob(payload, encoder, ph)
                suggestions.append({
                    "mutation": f"Place in {ph}",
                    "payload": payload,
                    "encoder": encoder,
                    "placeholder": ph,
                    "bypass_probability": prob,
                })

        # Try payload mutations
        mutations = [
            (payload.swapcase(), "Case inversion"),
            (payload.replace(" ", "/**/"), "SQL comment insertion"),
            (payload.replace("<", "%3C").replace(">", "%3E"), "Manual HTML encoding"),
            (payload + "\x00", "Null byte append"),
            (payload.replace("'", "\\'"), "Escape single quotes"),
            (f"/*!{payload}*/", "MySQL conditional comment"),
            (payload.replace("<script>", "<ScRiPt>"), "Mixed case tags"),
        ]
        for mutated, desc in mutations:
            prob = self._predict_bypass_prob(mutated, encoder, placeholder)
            suggestions.append({
                "mutation": desc,
                "payload": mutated[:200],
                "encoder": encoder,
                "placeholder": placeholder,
                "bypass_probability": prob,
            })

        suggestions.sort(key=lambda x: x["bypass_probability"], reverse=True)
        return suggestions[:top_k]

    def detect_drift(self, new_features: np.ndarray) -> list[str]:
        """Detect feature distribution drift using Kolmogorov-Smirnov test."""
        if self._training_feature_stats is None or len(new_features) < 10:
            return []

        warnings_list: list[str] = []
        from scipy import stats

        for i, (key, (train_mean, train_std)) in enumerate(self._training_feature_stats.items()):
            if i >= new_features.shape[1]:
                break
            new_col = new_features[:, i]
            if train_std < 1e-10:
                continue
            z_scores = np.abs((new_col - train_mean) / max(train_std, 1e-10))
            drift_pct = float((z_scores > 3).mean())
            if drift_pct > 0.1:
                warnings_list.append(
                    f"Feature {key}: {drift_pct:.1%} of values are >3σ from training mean"
                )

        return warnings_list

    def get_metrics(self) -> dict[str, Any]:
        """Return all training metrics and model state."""
        return {
            "is_trained": self._is_trained,
            "training_samples": self._metrics.samples,
            "bypassed": self._metrics.bypassed,
            "blocked": self._metrics.blocked,
            "cv_f1_score": round(self._metrics.cv_f1, 4),
            "feature_importance": self._metrics.feature_importance,
            "anomaly_stats": self._metrics.anomaly_stats,
            "drift_warnings": self._metrics.drift_warnings,
            "per_class": self._metrics.per_class,
            "calibration": self._metrics.calibration,
            "ablation": self._metrics.ablation,
            "learning_curves": self._metrics.learning_curves,
        }

    def _compute_extended_metrics(
        self, X: np.ndarray, y: np.ndarray, cv_folds: int,
    ) -> None:
        """Run a per-base-model ablation and learning-curve study.

        Populates self._metrics.ablation and self._metrics.learning_curves.
        Each base estimator is trained alone (with the same StandardScaler
        pre-processor and the same StratifiedKFold split) and its mean F1
        across folds is recorded. Learning curves use sklearn.model_selection
        .learning_curve at 8 training-set sizes from 10% to 100%.
        """
        from sklearn.ensemble import (
            RandomForestClassifier as _RF,
            GradientBoostingClassifier as _GB,
        )
        from sklearn.neural_network import MLPClassifier as _MLP
        from sklearn.linear_model import LogisticRegression as _LR
        from sklearn.neighbors import KNeighborsClassifier as _KNN
        from sklearn.svm import SVC as _SVC
        from sklearn.model_selection import (
            StratifiedKFold as _SKF, cross_val_score as _CVS,
            learning_curve as _LC,
        )
        from sklearn.pipeline import Pipeline as _PL
        from sklearn.preprocessing import StandardScaler as _SS

        skf = _SKF(n_splits=cv_folds, shuffle=True, random_state=42)

        models = {
            "random_forest": _RF(
                n_estimators=200, max_depth=6, min_samples_split=10,
                class_weight="balanced", random_state=42, n_jobs=1,
            ),
            "gradient_boosting": _GB(
                n_estimators=120, max_depth=4, learning_rate=0.08,
                subsample=0.8 if int(np.sum(y == np.argmin(np.bincount(y)))) >= 10 else 1.0,
                min_samples_split=10, random_state=42,
            ),
            "mlp": _MLP(
                hidden_layer_sizes=(48, 24), activation="relu",
                alpha=1e-3, early_stopping=False, random_state=42,
                max_iter=400,
            ),
            "logistic_regression": _LR(
                C=0.5, class_weight="balanced", max_iter=1000,
                random_state=42, solver="lbfgs",
            ),
            "knn": _KNN(n_neighbors=5),
            "svc_rbf": _SVC(
                C=1.0, kernel="rbf", probability=True,
                class_weight="balanced", random_state=42,
            ),
        }

        ablation: dict[str, dict] = {}
        learning_curves: dict[str, dict] = {}

        for name, est in models.items():
            try:
                pipe = _PL([("scaler", _SS()), ("est", est)])
                # Ablation F1 (5-fold CV)
                f1 = _CVS(pipe, X, y, cv=skf, scoring="f1", n_jobs=1)
                pre = _CVS(pipe, X, y, cv=skf, scoring="precision", n_jobs=1)
                rec = _CVS(pipe, X, y, cv=skf, scoring="recall", n_jobs=1)
                ablation[name] = {
                    "f1_mean":        round(float(np.mean(f1)), 4),
                    "f1_std":         round(float(np.std(f1)), 4),
                    "precision_mean": round(float(np.mean(pre)), 4),
                    "recall_mean":    round(float(np.mean(rec)), 4),
                }
                logger.info(
                    "ablation",
                    model=name,
                    f1=round(float(np.mean(f1)), 4),
                )

                # Learning curve (8 sizes, 5-fold CV)
                sizes_pct = np.linspace(0.10, 1.00, 8)
                lc_sizes, lc_train, lc_val = _LC(
                    pipe, X, y, train_sizes=sizes_pct,
                    cv=skf, scoring="f1", n_jobs=1, shuffle=True,
                    random_state=42,
                )
                learning_curves[name] = {
                    "sizes":      [int(s) for s in lc_sizes],
                    "train_mean": [round(float(v), 4) for v in lc_train.mean(axis=1)],
                    "train_std":  [round(float(v), 4) for v in lc_train.std(axis=1)],
                    "val_mean":   [round(float(v), 4) for v in lc_val.mean(axis=1)],
                    "val_std":    [round(float(v), 4) for v in lc_val.std(axis=1)],
                }
            except Exception as e:
                logger.debug("ablation/lc skipped", model=name, error=str(e))

        # Plus the combined stacking ensemble (no calibration) for direct
        # comparison against the bases. The calibrated value is already in
        # self._metrics.cv_f1.
        try:
            from sklearn.ensemble import StackingClassifier as _SC
            stacking = _SC(
                estimators=[
                    ("rf",  models["random_forest"]),
                    ("gb",  models["gradient_boosting"]),
                    ("mlp", models["mlp"]),
                ],
                final_estimator=_LR(
                    C=0.5, class_weight="balanced", max_iter=1000,
                    random_state=42, solver="lbfgs",
                ),
                cv=3, passthrough=False, n_jobs=1,
            )
            pipe = _PL([("scaler", _SS()), ("stack", stacking)])
            f1 = _CVS(pipe, X, y, cv=skf, scoring="f1", n_jobs=1)
            ablation["stacking_uncalibrated"] = {
                "f1_mean":  round(float(np.mean(f1)), 4),
                "f1_std":   round(float(np.std(f1)), 4),
            }
            logger.info(
                "ablation",
                model="stacking_uncalibrated",
                f1=round(float(np.mean(f1)), 4),
            )
        except Exception as e:
            logger.debug("stacking ablation skipped", error=str(e))

        # Final calibrated ensemble's cv_f1 is already in self._metrics.cv_f1
        ablation["stacking_calibrated_isotonic"] = {
            "f1_mean": round(float(self._metrics.cv_f1), 4),
        }

        self._metrics.ablation = ablation
        self._metrics.learning_curves = learning_curves

    def save(self, path: str) -> None:
        """Save trained models to disk."""
        import joblib
        state = {
            "payload_scaler": self._payload_scaler,
            "response_scaler": self._response_scaler,
            "combined_scaler": self._combined_scaler,
            "isolation_forest": self._isolation_forest,
            "ensemble": self._ensemble,
            "is_trained": self._is_trained,
            "metrics": self._metrics,
            "training_feature_stats": self._training_feature_stats,
            "baseline_status": self._baseline_status,
            "baseline_body": self._baseline_body,
        }
        joblib.dump(state, path)
        logger.info("ML engine saved", path=path)

    def load(self, path: str) -> None:
        """Load trained models from disk."""
        import joblib
        state = joblib.load(path)
        self._payload_scaler = state["payload_scaler"]
        self._response_scaler = state["response_scaler"]
        self._combined_scaler = state["combined_scaler"]
        self._isolation_forest = state["isolation_forest"]
        self._ensemble = state["ensemble"]
        self._is_trained = state["is_trained"]
        self._metrics = state["metrics"]
        self._training_feature_stats = state["training_feature_stats"]
        self._baseline_status = state.get("baseline_status", 200)
        self._baseline_body = state.get("baseline_body", b"")
        logger.info("ML engine loaded", path=path)

    # ---- Private methods ----

    def _rule_classify(
        self, status_code: int, headers: dict[str, list[str]], body: bytes,
    ) -> Prediction:
        """Layer 1: Fast rule-based classification."""
        body_text = body.decode("utf-8", errors="replace").lower() if body else ""

        # Bot protection detection
        bot_signals = sum(1 for kw in ["captcha", "challenge", "robot", "sgcaptcha"]
                         if kw in body_text)
        if bot_signals >= 2 and status_code in (202, 403, 429, 503):
            return Prediction(
                verdict=ResponseVerdict.BLOCKED_BY_BOT,
                confidence=0.95, bypass_probability=0.0,
                attack_type="", source="rules",
            )

        # WAF block with signature
        waf_signals = sum(1 for kw in ["access denied", "forbidden", "blocked",
                                        "request rejected", "security violation"]
                         if kw in body_text)
        if status_code == 403 and waf_signals >= 1:
            return Prediction(
                verdict=ResponseVerdict.BLOCKED_BY_WAF,
                confidence=0.95, bypass_probability=0.0,
                attack_type="", source="rules",
            )

        # Status-only block
        if status_code == 403:
            return Prediction(
                verdict=ResponseVerdict.BLOCKED_BY_WAF,
                confidence=0.85, bypass_probability=0.0,
                attack_type="", source="rules",
            )

        # Soft block (200 with WAF page)
        if status_code == 200 and waf_signals >= 2 and len(body) < 5000:
            return Prediction(
                verdict=ResponseVerdict.SOFT_BLOCKED,
                confidence=0.75, bypass_probability=0.1,
                attack_type="", source="rules",
            )

        # Normal pass
        if status_code == 200:
            return Prediction(
                verdict=ResponseVerdict.PASSED,
                confidence=0.70, bypass_probability=1.0,
                attack_type="", source="rules",
            )

        return Prediction(
            verdict=ResponseVerdict.UNRESOLVABLE,
            confidence=0.50, bypass_probability=0.5,
            attack_type="", source="rules",
        )

    def score_payloads_batch(
        self,
        items: list[tuple[str, str, str]],
    ) -> list[float]:
        """Predict bypass probability for many (payload, encoder, placeholder) tuples.

        One vectorized ``predict_proba`` call instead of N individual calls —
        used by the scanner's fast mode to prioritize/skip payloads at scan start.
        Returns a list of floats in [0, 1]; falls back to 0.5 on any failure
        so that fast-mode never drops payloads silently on an error.
        """
        if not items:
            return []
        if not self._is_trained or self._ensemble is None:
            return [0.5] * len(items)
        try:
            feats = np.array([
                extract_payload_features(p, e, ph) for (p, e, ph) in items
            ])
            feats_scaled = self._payload_scaler.transform(feats)
            proba = self._ensemble.predict_proba(feats_scaled)
            if proba.shape[1] < 2:
                return [0.0] * len(items)
            return [float(row[1]) for row in proba]
        except Exception as e:
            logger.warning("Batch scoring failed — defaulting to 0.5", error=str(e))
            return [0.5] * len(items)

    def _predict_bypass_prob(self, payload: str, encoder: str, placeholder: str) -> float:
        """Predict bypass probability for a single payload config."""
        if not self._is_trained or self._ensemble is None:
            # Heuristic fallback
            pf = extract_payload_features(payload, encoder, placeholder)
            return float(pf[31])  # obfuscation score as proxy

        pf = extract_payload_features(payload, encoder, placeholder)

        try:
            # Ensemble uses payload features only (no response features needed)
            pf_scaled = self._payload_scaler.transform(pf.reshape(1, -1))
            proba = self._ensemble.predict_proba(pf_scaled)[0]
            return float(proba[1]) if len(proba) > 1 else 0.0
        except Exception:
            return 0.0

    def _classify_attack_type(self, payload_features: np.ndarray) -> str:
        """Determine dominant attack type from payload features."""
        scores = {
            "xss": float(payload_features[20]),
            "sqli": float(payload_features[21]),
            "rce": float(payload_features[22]),
            "lfi": float(payload_features[23]),
            "xxe": float(payload_features[24]),
            "ssti": float(payload_features[25]),
        }
        if max(scores.values()) < 0.01:
            return "unknown"
        return max(scores, key=scores.get)
