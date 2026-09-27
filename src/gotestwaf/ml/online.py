"""Online ML intelligence — runs DURING the scan, not after.

Provides real-time capabilities:
1. Response fingerprinting — clusters WAF responses to detect soft blocks,
   rate limits, CAPTCHAs, and other hidden block behaviors
2. Adaptive payload skipping — learns which encoder+placeholder combos are
   always blocked and skips them to save time
3. Bypass pattern detection — identifies which payload features correlate
   with bypass and prioritizes similar payloads
4. Rate limit detection — detects when WAF starts throttling

Architecture:
    - Response fingerprints are hashed (body structure, not content)
    - MiniBatch online updates every N requests (no full retrain)
    - Lightweight: <1ms per decision, no sklearn needed for online phase
"""

from __future__ import annotations

import hashlib
import math
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass(slots=True)
class ResponseFingerprint:
    """Structural fingerprint of a WAF response (ignores dynamic content)."""
    status_code: int = 0
    body_length_bucket: int = 0  # Bucketed: 0-100, 100-1K, 1K-10K, 10K+
    content_type: str = ""
    has_form: bool = False
    has_script: bool = False
    body_structure_hash: str = ""  # Hash of HTML structure (tags only, no text)

    def key(self) -> str:
        return f"{self.status_code}|{self.body_length_bucket}|{self.content_type}|{self.body_structure_hash[:8]}"


@dataclass
class ResponseCluster:
    """A cluster of similar WAF responses."""
    fingerprint: ResponseFingerprint
    count: int = 0
    label: str = ""  # "block", "pass", "softblock", "ratelimit", "captcha", "unknown"
    sample_body: bytes = b""  # First response body for reference
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class ComboStats:
    """Stats for an encoder+placeholder combination."""
    blocked: int = 0
    passed: int = 0
    total: int = 0
    skip_predicted: bool = False


class OnlineMLEngine:
    """Real-time ML intelligence that runs during scanning.

    Unlike the batch HybridMLEngine that trains after scanning,
    this engine makes decisions in real-time:
    - Should we skip this payload? (predicted 99% block)
    - Is this a soft-block? (200 status but block page)
    - Is the WAF rate-limiting us? (response pattern changed)
    - Which combos have bypass potential? (for adaptive round)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()  # Reentrant: get_stats() calls get_bypass_combos()

        # Response clustering
        self._clusters: dict[str, ResponseCluster] = {}
        self._baseline_fingerprint: ResponseFingerprint | None = None

        # Combo tracking (encoder+placeholder → stats)
        self._combo_stats: dict[str, ComboStats] = defaultdict(ComboStats)

        # Payload feature tracking
        self._bypass_features: list[dict[str, float]] = []
        self._block_features: list[dict[str, float]] = []

        # Rate limit detection
        self._recent_statuses: list[int] = []
        self._rate_limit_detected = False
        self._rate_limit_start: float = 0.0

        # Counters
        self._total_requests = 0
        self._total_skipped = 0
        self._soft_blocks_found = 0
        self._model_version = 0

        # Adaptive thresholds (learned during scan)
        self._skip_threshold = 0.97  # Skip combo if >97% blocked
        self._min_samples_to_skip = 8  # Need at least 8 samples before skipping

    def set_baseline(self, status_code: int, headers: dict[str, list[str]], body: bytes) -> None:
        """Capture baseline response fingerprint for comparison."""
        with self._lock:
            self._baseline_fingerprint = _fingerprint_response(status_code, headers, body)
            cluster = ResponseCluster(
                fingerprint=self._baseline_fingerprint,
                count=1, label="baseline",
                sample_body=body[:2000],
                first_seen=time.monotonic(), last_seen=time.monotonic(),
            )
            self._clusters[self._baseline_fingerprint.key()] = cluster

    def record_result(
        self,
        payload: str,
        encoder: str,
        placeholder: str,
        status_code: int,
        headers: dict[str, list[str]],
        body: bytes,
        was_blocked: bool,
    ) -> None:
        """Record a scan result for online learning. Thread-safe."""
        with self._lock:
            self._total_requests += 1

            # 1. Cluster the response
            fp = _fingerprint_response(status_code, headers, body)
            key = fp.key()
            now = time.monotonic()

            if key not in self._clusters:
                label = self._classify_cluster(fp, body, was_blocked)
                self._clusters[key] = ResponseCluster(
                    fingerprint=fp, count=1, label=label,
                    sample_body=body[:2000],
                    first_seen=now, last_seen=now,
                )
                if label == "softblock":
                    self._soft_blocks_found += 1
                    logger.info(
                        "Soft-block detected! 200 status but block page",
                        status=status_code, body_len=len(body),
                        structure_hash=fp.body_structure_hash[:12],
                    )
            else:
                self._clusters[key].count += 1
                self._clusters[key].last_seen = now

            # 2. Track encoder+placeholder combo
            combo_key = f"{encoder}|{placeholder}"
            stats = self._combo_stats[combo_key]
            stats.total += 1
            if was_blocked:
                stats.blocked += 1
            else:
                stats.passed += 1

            # Adapt the skip-threshold to the WAF's overall block rate so the
            # feature actually fires for high-blocking WAFs. Previously the
            # threshold was a hardcoded 0.97 magic constant — for a WAF that
            # blocks 95% of everything (common for managed-rule WAFs in
            # Prevention mode), no combo's per-bucket rate ever exceeded
            # 0.97 and skip-prediction was effectively dead code.
            if self._total_requests == 50:
                total_blocked = sum(s.blocked for s in self._combo_stats.values())
                overall_block_rate = total_blocked / max(self._total_requests, 1)
                # Sit slightly above the overall rate so we only skip combos
                # that block MORE consistently than the WAF average.
                self._skip_threshold = max(0.85, min(0.97, overall_block_rate + 0.05))

            # Update skip prediction
            if stats.total >= self._min_samples_to_skip:
                block_rate = stats.blocked / stats.total
                stats.skip_predicted = block_rate >= self._skip_threshold

            # 3. Track bypass features
            if not was_blocked:
                self._bypass_features.append({
                    "length": len(payload),
                    "entropy": _quick_entropy(payload),
                    "special_ratio": sum(1 for c in payload if not c.isalnum()) / max(len(payload), 1),
                    "encoder": hash(encoder) % 100 / 100,
                    "placeholder": hash(placeholder) % 100 / 100,
                })

            # 4. Rate limit detection
            self._recent_statuses.append(status_code)
            if len(self._recent_statuses) > 20:
                self._recent_statuses = self._recent_statuses[-20:]
            self._detect_rate_limit()

    def should_skip(self, encoder: str, placeholder: str) -> bool:
        """Should this encoder+placeholder combo be skipped?

        Returns True if the model predicts >97% chance of block
        based on observed results for this combo.
        """
        with self._lock:
            combo_key = f"{encoder}|{placeholder}"
            stats = self._combo_stats.get(combo_key)
            if stats is None:
                return False
            if stats.skip_predicted:
                self._total_skipped += 1
                return True
            return False

    def is_rate_limited(self) -> bool:
        """Has rate limiting been detected?"""
        return self._rate_limit_detected

    def get_enhanced_classification(
        self, status_code: int, headers: dict[str, list[str]], body: bytes,
    ) -> tuple[str, float]:
        """Enhanced block/pass classification using response clustering.

        Returns (classification, confidence) where classification is:
        "block", "pass", "softblock", "ratelimit", "captcha"
        """
        fp = _fingerprint_response(status_code, headers, body)
        key = fp.key()

        with self._lock:
            cluster = self._clusters.get(key)
            if cluster is not None:
                return cluster.label, min(0.95, 0.5 + cluster.count * 0.05)

            # No cluster match — classify under lock (reads _baseline_fingerprint)
            label = self._classify_cluster(fp, body, status_code in (403, 401, 429, 500))
            return label, 0.6

    def get_bypass_combos(self) -> list[tuple[str, str, float]]:
        """Return encoder+placeholder combos ranked by bypass rate.

        Returns list of (encoder, placeholder, bypass_rate) sorted by rate.
        """
        with self._lock:
            combos = []
            for combo_key, stats in self._combo_stats.items():
                if stats.total < 3:
                    continue
                parts = combo_key.split("|", 1)
                if len(parts) != 2:
                    continue
                bypass_rate = stats.passed / stats.total
                if bypass_rate > 0:
                    combos.append((parts[0], parts[1], bypass_rate))
            combos.sort(key=lambda x: -x[2])
            return combos

    def get_stats(self) -> dict[str, Any]:
        """Return current online ML stats."""
        with self._lock:
            cluster_summary = {}
            for key, cluster in self._clusters.items():
                label = cluster.label
                cluster_summary.setdefault(label, 0)
                cluster_summary[label] += cluster.count

            skippable = [k for k, v in self._combo_stats.items() if v.skip_predicted]

            return {
                "total_requests": self._total_requests,
                "total_skipped": self._total_skipped,
                "response_clusters": len(self._clusters),
                "cluster_distribution": cluster_summary,
                "soft_blocks_detected": self._soft_blocks_found,
                "rate_limit_detected": self._rate_limit_detected,
                "skippable_combos": skippable,
                "bypass_combos": self.get_bypass_combos()[:5],
                "skip_savings_pct": round(self._total_skipped / max(self._total_requests, 1) * 100, 1),
            }

    def _classify_cluster(
        self, fp: ResponseFingerprint, body: bytes, was_blocked: bool,
    ) -> str:
        """Classify a response cluster using fingerprint analysis."""
        body_lower = body[:5000].decode("utf-8", errors="replace").lower()

        # CAPTCHA / bot protection
        captcha_signals = sum(1 for kw in ("captcha", "challenge", "robot", "verify", "sgcaptcha")
                             if kw in body_lower)
        if captcha_signals >= 2:
            return "captcha"

        # Rate limit
        if fp.status_code in (429, 503) or "rate limit" in body_lower or "too many" in body_lower:
            return "ratelimit"

        # Clear block
        if fp.status_code in (403, 401, 406):
            return "block"

        # Soft block detection: 200 status but looks like a block page
        if fp.status_code == 200 and self._baseline_fingerprint is not None:
            baseline_key = self._baseline_fingerprint.key()
            if fp.key() != baseline_key:
                # Different HTML structure from baseline = suspicious
                waf_signals = sum(1 for kw in (
                    "blocked", "denied", "forbidden", "rejected",
                    "security", "firewall", "waf", "violation",
                    "not allowed", "access denied", "request rejected",
                    "error 1020", "ray id", "attention required",
                ) if kw in body_lower)

                # Strong signal: WAF keywords + different body size
                if waf_signals >= 1 and fp.body_length_bucket != self._baseline_fingerprint.body_length_bucket:
                    return "softblock"

                # Medium signal: response is much smaller than baseline (stripped block page)
                if fp.body_length_bucket < self._baseline_fingerprint.body_length_bucket and waf_signals >= 1:
                    return "softblock"

                # Weak signal: completely different HTML structure but no WAF keywords
                # (could be a different page, not a block — don't classify as softblock)

        # Server errors (5xx) commonly indicate WAF interference / origin
        # rejection, regardless of whether the caller's status-code heuristic
        # already flagged this as blocked. The previous `not was_blocked`
        # guard made this dead code for status 500 (since the caller passes
        # `was_blocked=True` for 500), and the only path that mattered was
        # the simpler `if was_blocked` below.
        if fp.status_code in (500, 502, 504):
            return "block"

        if was_blocked:
            return "block"

        # If response matches baseline structure exactly, it's a pass
        if self._baseline_fingerprint is not None and fp.key() == self._baseline_fingerprint.key():
            return "pass"

        return "pass"

    def _detect_rate_limit(self) -> None:
        """Detect rate limiting from recent response patterns."""
        if len(self._recent_statuses) < 10:
            return

        recent = self._recent_statuses[-10:]
        rate_limit_codes = sum(1 for s in recent if s in (429, 503))

        if rate_limit_codes >= 5 and not self._rate_limit_detected:
            self._rate_limit_detected = True
            self._rate_limit_start = time.monotonic()
            logger.warning(
                "Rate limiting detected! Consider increasing --sendDelay",
                rate_limit_responses=rate_limit_codes,
                last_10_statuses=recent,
            )
        elif rate_limit_codes < 2 and self._rate_limit_detected:
            duration = time.monotonic() - self._rate_limit_start
            self._rate_limit_detected = False
            logger.info("Rate limiting resolved", duration=f"{duration:.0f}s")


def _fingerprint_response(
    status_code: int,
    headers: dict[str, list[str]],
    body: bytes,
) -> ResponseFingerprint:
    """Create a structural fingerprint of an HTTP response."""
    fp = ResponseFingerprint()
    fp.status_code = status_code

    # Body length bucket
    body_len = len(body)
    if body_len < 100:
        fp.body_length_bucket = 0
    elif body_len < 1000:
        fp.body_length_bucket = 1
    elif body_len < 10000:
        fp.body_length_bucket = 2
    else:
        fp.body_length_bucket = 3

    # Content type
    ct_values = headers.get("content-type", headers.get("Content-Type", []))
    fp.content_type = ct_values[0].split(";")[0].strip() if ct_values else ""

    # Body structure hash (extract HTML tags only, ignore text content)
    body_text = body[:5000].decode("utf-8", errors="replace")
    fp.has_form = "<form" in body_text.lower()
    fp.has_script = "<script" in body_text.lower()

    # Hash the tag structure (position-independent)
    import re
    tags = re.findall(r"</?[a-zA-Z][^>]*>", body_text[:3000])
    tag_structure = "|".join(t.split()[0].lower().strip("<>/") for t in tags[:50])
    fp.body_structure_hash = hashlib.md5(tag_structure.encode()).hexdigest()

    return fp


def _quick_entropy(data: str) -> float:
    """Fast Shannon entropy calculation."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in freq.values())
