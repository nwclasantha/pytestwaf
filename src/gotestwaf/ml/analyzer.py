"""Post-scan ML analyzer — trains on scan results and produces enhanced findings.

Integrates response classification and bypass prediction to provide:
1. Corrected block/pass/false-positive classifications
2. Bypass probability predictions for blocked payloads
3. Suggested mutations to test WAF weaknesses
4. Confidence scores for all findings
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

# Allow large CSV fields (128KB+ payloads in test cases)
# Use min() to avoid OverflowError on 64-bit Windows where sys.maxsize exceeds C long
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
from typing import Any

import structlog

from gotestwaf.ml.bypass_predictor import BypassPredictor, extract_payload_features
from gotestwaf.ml.response_classifier import (
    ResponseClass,
    WAFResponseClassifier,
    classify_response_rule_based,
    extract_features,
)

logger = structlog.get_logger()


class ScanAnalyzer:
    """Post-scan ML analysis engine.

    Loads scan results from CSV, trains models, and produces enhanced findings.
    """

    def __init__(self) -> None:
        self.classifier = WAFResponseClassifier()
        self.predictor = BypassPredictor()
        self._results: list[dict[str, str]] = []

    def load_csv_results(self, csv_path: str) -> int:
        """Load scan results from the exported CSV file.

        Args:
            csv_path: Path to the scan CSV export.

        Returns:
            Number of results loaded.
        """
        path = Path(csv_path)
        if not path.exists():
            logger.warning("CSV file not found", path=csv_path)
            return 0

        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            self._results = list(reader)

        logger.info("Loaded scan results", count=len(self._results))
        return len(self._results)

    def train_models(self) -> dict[str, Any]:
        """Train both models on the loaded scan data.

        Returns training metrics for both models.
        """
        if not self._results:
            return {"error": "no results loaded"}

        # Feed results to bypass predictor
        for row in self._results:
            payload = row.get("Payload", "")
            encoder = row.get("Encoder", "Plain")
            placeholder = row.get("Placeholder", "URLParam")
            check_status = row.get("Check Status", "")

            was_blocked = check_status == "blocked"
            self.predictor.add_result(payload, encoder, placeholder, was_blocked)

        # Train bypass predictor
        bypass_metrics = self.predictor.train()

        return {
            "bypass_predictor": bypass_metrics,
            "total_results": len(self._results),
        }

    def analyze_findings(self) -> dict[str, Any]:
        """Produce enhanced findings with ML confidence scores.

        Returns comprehensive analysis with:
        - Corrected classifications
        - Per-test-case confidence
        - Bypass predictions for blocked payloads
        - Suggested mutations
        """
        if not self._results:
            return {"error": "no results loaded"}

        blocked_count = 0
        passed_count = 0
        unresolved_count = 0
        high_confidence_blocks = 0
        high_confidence_passes = 0
        low_confidence_results = []
        bypass_candidates = []
        false_positive_candidates = []

        for row in self._results:
            payload = row.get("Payload", "")
            encoder = row.get("Encoder", "Plain")
            placeholder = row.get("Placeholder", "URLParam")
            check_status = row.get("Check Status", "")
            test_set = row.get("Set", "")
            test_case = row.get("Case", "")
            test_result = row.get("Test Result", "")
            status_code = int(row.get("Response Code", "0") or "0")

            is_attack = "false" not in test_set.lower()

            if check_status == "blocked":
                blocked_count += 1

                # For blocked attacks — predict if mutation could bypass
                pred = self.predictor.predict_bypass_probability(payload, encoder, placeholder)
                if pred["bypass_probability"] > 0.4:
                    suggestions = self.predictor.suggest_mutations(payload, encoder, placeholder, top_k=3)
                    bypass_candidates.append({
                        "payload": payload[:100],
                        "encoder": encoder,
                        "placeholder": placeholder,
                        "test_set": test_set,
                        "test_case": test_case,
                        "bypass_probability": pred["bypass_probability"],
                        "confidence": pred["confidence"],
                        "attack_type": pred["payload_type"],
                        "top_mutations": suggestions[:3],
                    })

                if pred["confidence"] > 0.7:
                    high_confidence_blocks += 1

            elif check_status == "passed":
                passed_count += 1

                if not is_attack:
                    # Benign traffic that was passed — correct behavior
                    high_confidence_passes += 1
                else:
                    # Attack that bypassed — flag for investigation
                    features = extract_payload_features(payload, encoder, placeholder)
                    bypass_candidates.append({
                        "payload": payload[:100],
                        "encoder": encoder,
                        "placeholder": placeholder,
                        "test_set": test_set,
                        "test_case": test_case,
                        "bypass_probability": 1.0,
                        "confidence": 0.95,
                        "attack_type": _classify_attack(payload),
                        "evasion_techniques": _detect_evasion(payload),
                        "status": "CONFIRMED_BYPASS",
                    })
            else:
                unresolved_count += 1
                low_confidence_results.append({
                    "payload": payload[:80],
                    "test_case": test_case,
                    "status_code": status_code,
                })

        # Analyze false positives (benign traffic that was blocked)
        for row in self._results:
            test_set = row.get("Set", "")
            check_status = row.get("Check Status", "")
            if "false" in test_set.lower() and check_status == "blocked":
                payload = row.get("Payload", "")
                false_positive_candidates.append({
                    "payload": payload[:100],
                    "test_case": row.get("Case", ""),
                    "likely_cause": _analyze_false_positive_cause(payload),
                })

        return {
            "summary": {
                "total_tested": len(self._results),
                "blocked": blocked_count,
                "passed": passed_count,
                "unresolved": unresolved_count,
                "high_confidence_blocks": high_confidence_blocks,
                "high_confidence_passes": high_confidence_passes,
                "low_confidence_count": len(low_confidence_results),
            },
            "confirmed_bypasses": [b for b in bypass_candidates if b.get("status") == "CONFIRMED_BYPASS"],
            "potential_bypass_mutations": [b for b in bypass_candidates if b.get("status") != "CONFIRMED_BYPASS"][:20],
            "false_positive_analysis": {
                "count": len(false_positive_candidates),
                "candidates": false_positive_candidates[:20],
            },
            "low_confidence_results": low_confidence_results[:10],
            "model_metrics": self.predictor.training_summary if hasattr(self.predictor, "training_summary") else {},
        }


def _classify_attack(payload: str) -> str:
    features = extract_payload_features(payload)
    scores = {
        "xss": features.xss_score,
        "sqli": features.sqli_score,
        "rce": features.rce_score,
        "lfi": features.lfi_score,
    }
    if max(scores.values()) == 0:
        return "unknown"
    return max(scores, key=scores.get)


def _detect_evasion(payload: str) -> list[str]:
    techniques = []
    if "\\u" in payload:
        techniques.append("unicode_escape")
    if "%" in payload:
        techniques.append("url_encoding")
    if "<x>" in payload:
        techniques.append("tag_fragmentation")
    has_upper = any(c.isupper() for c in payload)
    has_lower = any(c.islower() for c in payload)
    if has_upper and has_lower:
        techniques.append("mixed_case")
    return techniques


def _analyze_false_positive_cause(payload: str) -> str:
    """Attempt to explain why a benign payload was blocked."""
    pl = payload.lower()
    if any(kw in pl for kw in ["select", "union", "drop", "insert", "delete"]):
        return "SQL-like keywords in benign text"
    if "<" in payload and ">" in payload:
        return "HTML-like angle brackets in benign text"
    if "../" in payload or "..\\" in payload:
        return "Path-like sequences in benign text"
    if "'" in payload or '"' in payload:
        return "Quote characters triggering injection rules"
    if len(payload) > 1000:
        return "Large payload size triggering length-based rules"
    return "WAF rule too aggressive for this content pattern"
