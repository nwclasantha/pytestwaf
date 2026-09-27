"""Tests for report generation — chart data, HTML preparation, format validation."""

from __future__ import annotations

from datetime import datetime

import pytest

from gotestwaf.db.database import DB
from gotestwaf.db.models import Case, Info, Placeholder
from gotestwaf.db.statistics import get_statistics
from gotestwaf.report.chart import Pair, generate_chart_data, get_indicators_and_items, update_counters
from gotestwaf.report.html import (
    prepare_html_full_report,
    render_full_report_to_html,
    reset_report_cache,
)


def _make_stat():
    cases = [
        Case(payloads=["p1", "p2"], encoders=["Plain"], placeholders=[Placeholder(name="URLParam")],
             type="XSS", set="owasp", name="xss", is_true_positive=True),
        Case(payloads=["benign"], encoders=["Plain"], placeholders=[Placeholder(name="URLParam")],
             type="FP", set="false-pos", name="texts", is_true_positive=False),
    ]
    db = DB.from_test_cases(cases)
    db.update_blocked_tests(Info(set="owasp", case="xss", payload="p1", encoder="Plain",
                                  placeholder="URLParam", response_status_code=403, type="XSS"))
    db.update_passed_tests(Info(set="owasp", case="xss", payload="p2", encoder="Plain",
                                 placeholder="URLParam", response_status_code=200, type="XSS"))
    db.update_passed_tests(Info(set="false-pos", case="texts", payload="benign", encoder="Plain",
                                 placeholder="URLParam", response_status_code=200, type="FP"))
    return get_statistics(db, False, False)


class TestChartData:
    def test_update_counters(self) -> None:
        from gotestwaf.db.statistics import TestDetails
        counters: dict[str, dict[str, Pair]] = {}
        td = TestDetails(test_set="owasp", type="XSS")
        update_counters(td, counters, is_blocked=True)
        assert counters["app"]["xss"].blocked == 1

    def test_update_counters_api(self) -> None:
        from gotestwaf.db.statistics import TestDetails
        counters: dict[str, dict[str, Pair]] = {}
        td = TestDetails(test_set="owasp-api", type="REST")
        update_counters(td, counters, is_blocked=False)
        assert counters["api"]["rest"].bypassed == 1

    def test_get_indicators_empty(self) -> None:
        counters: dict[str, dict[str, Pair]] = {}
        indicators, items = get_indicators_and_items(counters, "app")
        assert indicators == []
        assert items == []

    def test_generate_chart_data(self) -> None:
        stat = _make_stat()
        api_ind, api_items, app_ind, app_items = generate_chart_data(stat)
        # Should have app indicators for XSS
        assert len(app_ind) > 0 or len(api_ind) > 0


class TestHTMLReport:
    def setup_method(self) -> None:
        reset_report_cache()

    def test_prepare_report_has_all_keys(self) -> None:
        stat = _make_stat()
        data = prepare_html_full_report(stat, datetime.now(), "TestWAF", "http://test", "", [], False, False)
        assert "overall" in data
        assert "api_sec" in data
        assert "app_sec" in data
        assert "comparison_table" in data
        assert "wallarm_result" in data
        assert "true_positive_tests" in data
        assert "true_negative_tests" in data
        assert "total_sent" in data

    def test_overall_grade_has_mark(self) -> None:
        stat = _make_stat()
        data = prepare_html_full_report(stat, datetime.now(), "WAF", "http://t", "", [], False, False)
        assert "mark" in data["overall"]
        assert data["overall"]["mark"] in ("A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F", "N/A")

    def test_comparison_table_has_4_entries(self) -> None:
        stat = _make_stat()
        data = prepare_html_full_report(stat, datetime.now(), "WAF", "http://t", "", [], False, False)
        assert len(data["comparison_table"]) == 4

    def test_render_produces_html(self) -> None:
        stat = _make_stat()
        data = prepare_html_full_report(stat, datetime.now(), "WAF", "http://t", "", [], False, False)
        html = render_full_report_to_html(data)
        assert "<!DOCTYPE html>" in html
        assert "WAF" in html

    def test_render_contains_charts(self) -> None:
        stat = _make_stat()
        data = prepare_html_full_report(stat, datetime.now(), "WAF", "http://t", "", [], False, False)
        html = render_full_report_to_html(data)
        assert "<svg" in html

    def test_render_contains_comparison_table(self) -> None:
        stat = _make_stat()
        data = prepare_html_full_report(stat, datetime.now(), "WAF", "http://t", "", [], False, False)
        html = render_full_report_to_html(data)
        assert "ModSecurity" in html

    def test_include_payloads(self) -> None:
        stat = _make_stat()
        data = prepare_html_full_report(stat, datetime.now(), "WAF", "http://t", "", [], False, True)
        html = render_full_report_to_html(data)
        assert "Bypassed Payloads" in html or "bypass" in html.lower()

    def test_openapi_file_in_report(self) -> None:
        stat = _make_stat()
        data = prepare_html_full_report(stat, datetime.now(), "WAF", "http://t", "api.yaml", [], False, False)
        assert data["open_api_file"] == "api.yaml"

    def test_args_in_report(self) -> None:
        stat = _make_stat()
        data = prepare_html_full_report(stat, datetime.now(), "WAF", "http://t", "", ["--url=test", "--workers=5"], False, False)
        assert data["args"] == ["--url=test", "--workers=5"]

    def test_reset_cache_clears(self) -> None:
        stat = _make_stat()
        from gotestwaf.report.html import once_prepare_html_full_report, _cached_report_data
        d1 = once_prepare_html_full_report(stat, datetime.now(), "WAF1", "http://t", "", [], False, False)
        assert d1["waf_name"] == "WAF1"
        reset_report_cache()
        d2 = once_prepare_html_full_report(stat, datetime.now(), "WAF2", "http://t", "", [], False, False)
        assert d2["waf_name"] == "WAF2"
