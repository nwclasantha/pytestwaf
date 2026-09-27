"""Response time analysis — measures WAF latency impact.

Computes p50/p95/p99 latency for blocked vs bypassed vs benign requests,
calculates WAF processing overhead.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gotestwaf.db.database import DB


@dataclass(slots=True)
class LatencyStats:
    """Latency percentiles for a group of requests."""
    count: int = 0
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    mean_ms: float = 0.0
    min_ms: float = 0.0
    max_ms: float = 0.0

    def to_dict(self) -> dict[str, float]:
        return {
            "count": self.count, "p50_ms": round(self.p50_ms, 1),
            "p95_ms": round(self.p95_ms, 1), "p99_ms": round(self.p99_ms, 1),
            "mean_ms": round(self.mean_ms, 1), "min_ms": round(self.min_ms, 1),
            "max_ms": round(self.max_ms, 1),
        }


@dataclass
class LatencyAnalysis:
    """Complete latency analysis across request categories."""
    overall: LatencyStats = field(default_factory=LatencyStats)
    blocked: LatencyStats = field(default_factory=LatencyStats)
    bypassed: LatencyStats = field(default_factory=LatencyStats)
    failed: LatencyStats = field(default_factory=LatencyStats)
    waf_overhead_ms: float = 0.0
    by_attack_type: dict[str, LatencyStats] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "overall": self.overall.to_dict(),
            "blocked": self.blocked.to_dict(),
            "bypassed": self.bypassed.to_dict(),
            "failed": self.failed.to_dict(),
            "waf_overhead_ms": round(self.waf_overhead_ms, 1),
            "by_attack_type": {k: v.to_dict() for k, v in self.by_attack_type.items()},
        }


def _compute_stats(times: list[float]) -> LatencyStats:
    if not times:
        return LatencyStats()
    sorted_t = sorted(times)
    n = len(sorted_t)
    return LatencyStats(
        count=n,
        p50_ms=statistics.median(sorted_t),
        p95_ms=sorted_t[min(int(n * 0.95), n - 1)],
        p99_ms=sorted_t[min(int(n * 0.99), n - 1)],
        mean_ms=statistics.mean(sorted_t),
        min_ms=sorted_t[0],
        max_ms=sorted_t[-1],
    )


def compute_latency_analysis(db: DB) -> LatencyAnalysis:
    """Compute latency statistics from scan results."""
    analysis = LatencyAnalysis()

    all_times: list[float] = []
    blocked_times: list[float] = []
    bypassed_times: list[float] = []
    failed_times: list[float] = []
    by_type: dict[str, list[float]] = {}

    for t in db.blocked_tests:
        ms = getattr(t, 'response_time_ms', 0.0)
        if ms > 0:
            all_times.append(ms)
            blocked_times.append(ms)
            by_type.setdefault(t.type or "unknown", []).append(ms)

    for t in db.passed_tests:
        ms = getattr(t, 'response_time_ms', 0.0)
        if ms > 0:
            all_times.append(ms)
            bypassed_times.append(ms)
            by_type.setdefault(t.type or "unknown", []).append(ms)

    for t in db.failed_tests:
        ms = getattr(t, 'response_time_ms', 0.0)
        if ms > 0:
            all_times.append(ms)
            failed_times.append(ms)

    analysis.overall = _compute_stats(all_times)
    analysis.blocked = _compute_stats(blocked_times)
    analysis.bypassed = _compute_stats(bypassed_times)
    analysis.failed = _compute_stats(failed_times)

    # WAF overhead = mean blocked latency - mean bypassed latency
    if blocked_times and bypassed_times:
        analysis.waf_overhead_ms = statistics.mean(blocked_times) - statistics.mean(bypassed_times)

    for attack_type, times in by_type.items():
        analysis.by_attack_type[attack_type] = _compute_stats(times)

    return analysis
