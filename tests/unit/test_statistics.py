"""Comprehensive tests for statistics computation."""

from __future__ import annotations

import pytest

from gotestwaf.db.database import DB
from gotestwaf.db.models import Case, Info, Placeholder
from gotestwaf.db.statistics import get_statistics


def _make_db(
    tp_blocked: int = 0,
    tp_passed: int = 0,
    tp_na: int = 0,
    tp_failed: int = 0,
    tn_blocked: int = 0,
    tn_passed: int = 0,
    api_blocked: int = 0,
    api_passed: int = 0,
) -> DB:
    """Create a DB with controlled test results."""
    cases = [
        Case(payloads=["p"], encoders=["Plain"], placeholders=[Placeholder(name="URLParam")],
             type="XSS", set="owasp", name="xss", is_true_positive=True),
        Case(payloads=["p"], encoders=["Plain"], placeholders=[Placeholder(name="URLParam")],
             type="FP", set="false-pos", name="texts", is_true_positive=False),
    ]
    if api_blocked or api_passed:
        cases.append(Case(payloads=["p"], encoders=["Plain"], placeholders=[Placeholder(name="URLParam")],
                          type="REST", set="owasp-api", name="rest", is_true_positive=True))

    db = DB.from_test_cases(cases)

    for _ in range(tp_blocked):
        db.update_blocked_tests(Info(set="owasp", case="xss", payload="p", encoder="Plain", placeholder="URLParam", response_status_code=403))
    for _ in range(tp_passed):
        db.update_passed_tests(Info(set="owasp", case="xss", payload="p", encoder="Plain", placeholder="URLParam", response_status_code=200))
    for _ in range(tp_na):
        db.update_na_tests(Info(set="owasp", case="xss", payload="p", encoder="Plain", placeholder="URLParam"), False, False, True)
    for _ in range(tp_failed):
        db.update_failed_tests(Info(set="owasp", case="xss", payload="p", encoder="Plain", placeholder="URLParam"))

    for _ in range(tn_blocked):
        db.update_blocked_tests(Info(set="false-pos", case="texts", payload="p", encoder="Plain", placeholder="URLParam", response_status_code=403))
    for _ in range(tn_passed):
        db.update_passed_tests(Info(set="false-pos", case="texts", payload="p", encoder="Plain", placeholder="URLParam", response_status_code=200))

    for _ in range(api_blocked):
        db.update_blocked_tests(Info(set="owasp-api", case="rest", payload="p", encoder="Plain", placeholder="URLParam", response_status_code=403))
    for _ in range(api_passed):
        db.update_passed_tests(Info(set="owasp-api", case="rest", payload="p", encoder="Plain", placeholder="URLParam", response_status_code=200))

    return db


class TestStatisticsComputation:
    def test_all_blocked(self) -> None:
        db = _make_db(tp_blocked=10)
        stat = get_statistics(db, False, False)
        assert stat.true_positive_tests.resolved_blocked_requests_percentage == 100.0

    def test_all_passed(self) -> None:
        db = _make_db(tp_passed=10)
        stat = get_statistics(db, False, False)
        assert stat.true_positive_tests.resolved_blocked_requests_percentage == 0.0

    def test_mixed_results(self) -> None:
        db = _make_db(tp_blocked=7, tp_passed=3)
        stat = get_statistics(db, False, False)
        assert stat.true_positive_tests.resolved_blocked_requests_percentage == 70.0

    def test_empty_db(self) -> None:
        cases = [Case(payloads=["p"], encoders=["Plain"], placeholders=[Placeholder(name="URLParam")],
                       type="XSS", set="owasp", name="xss", is_true_positive=True)]
        db = DB.from_test_cases(cases)
        stat = get_statistics(db, False, False)
        assert stat.true_positive_tests.req_stats.all_requests_number == 0

    def test_false_positive_scoring(self) -> None:
        db = _make_db(tn_blocked=2, tn_passed=8)
        stat = get_statistics(db, False, False)
        assert stat.true_negative_tests.resolved_bypassed_requests_percentage == 80.0

    def test_api_sec_vs_app_sec_split(self) -> None:
        db = _make_db(tp_blocked=5, api_blocked=3, api_passed=2)
        stat = get_statistics(db, False, False)
        assert stat.true_positive_tests.app_sec_req_stats.blocked_requests_number == 5
        assert stat.true_positive_tests.api_sec_req_stats.blocked_requests_number == 3
        assert stat.true_positive_tests.api_sec_req_stats.bypassed_requests_number == 2

    def test_score_with_zero_blocked(self) -> None:
        """When no attacks are blocked, average should be 0.0 (not -1)."""
        db = _make_db(tp_passed=10)
        stat = get_statistics(db, False, False)
        assert stat.score.app_sec.average == 0.0

    def test_score_no_data(self) -> None:
        """When no data exists, score should be -1.0."""
        cases = [Case(payloads=["p"], encoders=["Plain"], placeholders=[Placeholder(name="URLParam")],
                       type="XSS", set="owasp", name="xss", is_true_positive=True)]
        db = DB.from_test_cases(cases)
        stat = get_statistics(db, False, False)
        assert stat.score.app_sec.true_positive == -1.0

    def test_ignore_unresolved(self) -> None:
        db = _make_db(tp_blocked=5, tp_na=5)
        stat_normal = get_statistics(db, False, False)
        stat_ignore = get_statistics(db, True, False)
        # With ignore_unresolved, unresolved count as bypassed
        assert stat_ignore.true_positive_tests.req_stats.bypassed_requests_number >= stat_normal.true_positive_tests.req_stats.bypassed_requests_number

    def test_summary_table_sorted(self) -> None:
        db = _make_db(tp_blocked=1, tn_passed=1)
        stat = get_statistics(db, False, False)
        if len(stat.true_positive_tests.summary_table) > 1:
            sets = [r.test_set for r in stat.true_positive_tests.summary_table]
            assert sets == sorted(sets)

    def test_scanned_paths(self) -> None:
        db = _make_db()
        db.add_to_scanned_paths("GET", "/api/test")
        db.add_to_scanned_paths("POST", "/api/test")
        db.add_to_scanned_paths("GET", "/api/other")
        stat = get_statistics(db, False, False)
        assert len(stat.paths) == 3
        # Verify sorted
        path_strs = [(p.path, p.method) for p in stat.paths]
        assert path_strs == sorted(path_strs)
