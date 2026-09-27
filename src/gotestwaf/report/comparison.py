"""WAF comparison — compare current scan with a previous scan report.

Usage: --compare=reports/previous-scan.json
Loads previous JSON report and generates side-by-side comparison.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CategoryDiff:
    """Difference for one attack category."""
    category: str = ""
    current_block_pct: float = 0.0
    previous_block_pct: float = 0.0
    delta: float = 0.0  # positive = improved
    status: str = ""  # "improved", "regressed", "unchanged"


@dataclass
class ComparisonReport:
    """Side-by-side comparison of two scans."""
    current_url: str = ""
    previous_url: str = ""
    current_waf: str = ""
    previous_waf: str = ""
    current_score: float = 0.0
    previous_score: float = 0.0
    score_delta: float = 0.0
    categories: list[CategoryDiff] = field(default_factory=list)
    improved_count: int = 0
    regressed_count: int = 0
    unchanged_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "current": {"url": self.current_url, "waf": self.current_waf, "score": round(self.current_score, 2)},
            "previous": {"url": self.previous_url, "waf": self.previous_waf, "score": round(self.previous_score, 2)},
            "score_delta": round(self.score_delta, 2),
            "improved": self.improved_count,
            "regressed": self.regressed_count,
            "unchanged": self.unchanged_count,
            "categories": [
                {"name": c.category, "current": round(c.current_block_pct, 1),
                 "previous": round(c.previous_block_pct, 1), "delta": round(c.delta, 1),
                 "status": c.status}
                for c in self.categories
            ],
        }


def load_previous_scan(json_path: str) -> dict[str, Any] | None:
    """Load a previous scan's JSON report."""
    try:
        path = Path(json_path)
        if not path.exists():
            logger.warning("Previous scan file not found", path=json_path)
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data
    except Exception as e:
        logger.warning("Failed to load previous scan", error=str(e))
        return None


def compare_scans(
    current_stat: Any,
    current_waf: str,
    current_url: str,
    previous_data: dict[str, Any],
) -> ComparisonReport:
    """Compare current scan statistics with previous scan data."""
    report = ComparisonReport(
        current_url=current_url,
        current_waf=current_waf,
        previous_url=previous_data.get("url", ""),
        previous_waf=previous_data.get("project_name", ""),
    )

    # Current score
    report.current_score = current_stat.score.average if current_stat.score.average >= 0 else 0

    # Previous score
    report.previous_score = previous_data.get("score", 0)
    if report.previous_score < 0:
        report.previous_score = 0

    report.score_delta = report.current_score - report.previous_score

    # Per-category comparison
    # Build current categories lookup
    current_cats: dict[str, float] = {}
    for row in current_stat.true_positive_tests.summary_table:
        current_cats[row.test_case] = row.percentage

    # Build previous categories lookup. The full-report JSON nests under
    # `summary.true_positive_tests.test_sets`, but the console-mode JSON
    # exporter writes `true_positive_tests.test_sets` at the top level —
    # without this fallback, supplying a console JSON to --compare would
    # silently produce an all-"new" comparison with no warning.
    prev_summary = previous_data.get("summary", {})
    prev_tp = prev_summary.get("true_positive_tests") or previous_data.get("true_positive_tests", {})
    prev_sets = prev_tp.get("test_sets", {})
    prev_cats: dict[str, float] = {}
    for test_set, cases in prev_sets.items():
        if isinstance(cases, dict):
            for case_name, case_data in cases.items():
                if isinstance(case_data, dict):
                    prev_cats[case_name] = case_data.get("percentage", 0)

    # Merge categories
    all_cats = sorted(set(list(current_cats.keys()) + list(prev_cats.keys())))
    for cat in all_cats:
        curr = current_cats.get(cat, -1)
        prev = prev_cats.get(cat, -1)

        if curr < 0 and prev < 0:
            continue

        diff = CategoryDiff(
            category=cat,
            current_block_pct=max(0, curr),
            previous_block_pct=max(0, prev),
        )

        if curr >= 0 and prev >= 0:
            diff.delta = curr - prev
            if diff.delta > 5:
                diff.status = "improved"
                report.improved_count += 1
            elif diff.delta < -5:
                diff.status = "regressed"
                report.regressed_count += 1
            else:
                diff.status = "unchanged"
                report.unchanged_count += 1
        elif curr >= 0:
            diff.status = "new"
        else:
            diff.status = "removed"

        report.categories.append(diff)

    return report
