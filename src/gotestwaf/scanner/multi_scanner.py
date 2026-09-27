"""Multi-target scanning — scan multiple URLs and compare results.

Usage:
    --url=https://dev.example.com,https://staging.example.com,https://prod.example.com
    --targets=targets.txt (one URL per line)
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from gotestwaf.config.config import Config
    from gotestwaf.db.statistics import Statistics

logger = structlog.get_logger()


@dataclass
class TargetResult:
    """Results for a single scan target."""
    url: str = ""
    waf_name: str = ""
    score: float = 0.0
    blocked: int = 0
    bypassed: int = 0
    total: int = 0
    block_rate: float = 0.0
    stat: Any = None
    ml_analysis: dict[str, Any] = field(default_factory=dict)


@dataclass
class ComparisonResult:
    """Comparison across multiple targets."""
    targets: list[TargetResult] = field(default_factory=list)
    best_target: str = ""
    worst_target: str = ""
    score_range: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "targets": [
                {"url": t.url, "waf": t.waf_name, "score": round(t.score, 2),
                 "blocked": t.blocked, "bypassed": t.bypassed, "total": t.total,
                 "block_rate": round(t.block_rate, 2)}
                for t in self.targets
            ],
            "best": self.best_target,
            "worst": self.worst_target,
            "score_range": round(self.score_range, 2),
        }


def parse_targets(url: str, targets_file: str) -> list[str]:
    """Parse target URLs from --url (comma-separated) or --targets file.

    Returns list of unique URLs.
    """
    urls: list[str] = []

    if url:
        urls.extend(u.strip() for u in url.split(",") if u.strip())

    if targets_file:
        try:
            from pathlib import Path
            content = Path(targets_file).read_text(encoding="utf-8")
            for line in content.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
        except Exception as e:
            logger.warning("Failed to read targets file", file=targets_file, error=str(e))

    # Deduplicate preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique.append(u)

    return unique


def build_config_for_target(base_cfg: Config, target_url: str, index: int) -> Config:
    """Create a Config copy for a specific target URL."""
    cfg = copy.deepcopy(base_cfg)
    cfg.url = target_url

    # Generate unique report name per target
    from urllib.parse import urlparse
    host = urlparse(target_url).hostname or f"target-{index}"
    cfg.report_name = f"waf-scan-{host.replace('.', '-')}"
    cfg.waf_name = "generic"  # Will be auto-detected

    return cfg


def compare_results(results: list[TargetResult]) -> ComparisonResult:
    """Compare scan results across multiple targets."""
    comparison = ComparisonResult(targets=results)

    if not results:
        return comparison

    scored = [r for r in results if r.total > 0]
    if scored:
        best = max(scored, key=lambda r: r.block_rate)
        worst = min(scored, key=lambda r: r.block_rate)
        comparison.best_target = best.url
        comparison.worst_target = worst.url
        comparison.score_range = best.block_rate - worst.block_rate

    return comparison
