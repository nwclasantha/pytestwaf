"""Tests for report generation."""

from __future__ import annotations

from datetime import datetime

import pytest

from gotestwaf.db.statistics import (
    RequestStats,
    Score,
    ScoreSet,
    Statistics,
    SummaryTableRow,
    TestsSummary,
)
from gotestwaf.report.console import render_console_report
from gotestwaf.report.helpers import get_grade, truncate_payload
from gotestwaf.report.report import IsNoneReportFormat, IsPdfOrHtmlReportFormat, ValidateReportFormat


class TestReportFormats:
    def test_validate_valid_formats(self) -> None:
        ValidateReportFormat(["pdf"])
        ValidateReportFormat(["json", "html"])
        ValidateReportFormat(["none"])

    def test_validate_unknown_format(self) -> None:
        from gotestwaf.errors import ReportError
        with pytest.raises(ReportError, match="unknown report format"):
            ValidateReportFormat(["docx"])

    def test_validate_none_conflicts(self) -> None:
        from gotestwaf.errors import ReportError
        with pytest.raises(ReportError, match="conflicts"):
            ValidateReportFormat(["none", "pdf"])

    def test_validate_duplicates(self) -> None:
        from gotestwaf.errors import ReportError
        with pytest.raises(ReportError, match="duplicated"):
            ValidateReportFormat(["pdf", "pdf"])

    def test_is_none_format(self) -> None:
        assert IsNoneReportFormat(["none"]) is True
        assert IsNoneReportFormat(["pdf"]) is False
        assert IsNoneReportFormat([]) is False

    def test_is_pdf_or_html(self) -> None:
        assert IsPdfOrHtmlReportFormat(["pdf"]) is True
        assert IsPdfOrHtmlReportFormat(["html"]) is True
        assert IsPdfOrHtmlReportFormat(["json"]) is False


class TestHelpers:
    def test_truncate_short_payload(self) -> None:
        payload = "short payload"
        assert truncate_payload(payload) == payload

    def test_truncate_long_payload(self) -> None:
        payload = "x" * 2000
        result = truncate_payload(payload)
        assert "truncated" in result
        assert len(result) < len(payload)

    def test_get_grade_na(self) -> None:
        grade = get_grade(0.0, na=True)
        assert grade["mark"] == "N/A"

    @pytest.mark.parametrize(
        "percentage,expected_mark",
        [
            (98.0, "A+"),
            (95.0, "A"),
            (91.0, "A-"),
            (85.0, "B"),
            (75.0, "C"),
            (65.0, "D"),
            (50.0, "F"),
        ],
        ids=["A+", "A", "A-", "B", "C", "D", "F"],
    )
    def test_get_grade_marks(self, percentage: float, expected_mark: str) -> None:
        grade = get_grade(percentage)
        assert grade["mark"] == expected_mark


class TestConsoleReport:
    def test_text_report(self, capsys: pytest.CaptureFixture[str]) -> None:
        stats = Statistics()
        stats.true_positive_tests.summary_table.append(
            SummaryTableRow(test_set="owasp", test_case="xss", percentage=75.0, sent=4, blocked=3, bypassed=1)
        )
        stats.true_positive_tests.req_stats = RequestStats(
            all_requests_number=4,
            blocked_requests_number=3,
            bypassed_requests_number=1,
            resolved_requests_number=4,
        )
        stats.true_positive_tests.resolved_blocked_requests_percentage = 75.0
        stats.score = ScoreSet(
            app_sec=Score(true_positive=75.0, true_negative=-1.0, average=75.0),
            api_sec=Score(true_positive=-1.0, true_negative=-1.0, average=-1.0),
            average=75.0,
        )

        render_console_report(stats, datetime.now(), "TestWAF", "http://test", [], False, "text")
        captured = capsys.readouterr()
        assert "True-Positive Tests:" in captured.out
        assert "xss" in captured.out
