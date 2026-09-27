"""Tests for database operations."""

from __future__ import annotations

import pytest

from gotestwaf.db.database import DB
from gotestwaf.db.helpers import calculate_percentage, is_api_test, is_false_positive_test, round_value
from gotestwaf.db.models import Case, Info, Placeholder
from gotestwaf.db.statistics import get_statistics


class TestHelpers:
    def test_round_value(self) -> None:
        assert round_value(45.365) == 45.37
        assert round_value(0.0) == 0.0
        assert round_value(float("nan")) == 0.0

    @pytest.mark.parametrize(
        "first,second,expected",
        [
            (50, 100, 50.0),
            (0, 100, 0.0),
            (100, 100, 100.0),
            (1, 0, 0.0),
            (0, 0, 0.0),
        ],
        ids=["half", "zero-numerator", "full", "zero-denominator", "both-zero"],
    )
    def test_calculate_percentage(self, first: int, second: int, expected: float) -> None:
        assert calculate_percentage(first, second) == expected

    def test_is_false_positive_test(self) -> None:
        assert is_false_positive_test("false-pos") is True
        assert is_false_positive_test("owasp") is False

    def test_is_api_test(self) -> None:
        assert is_api_test("owasp-api") is True
        assert is_api_test("owasp") is False


class TestDB:
    def test_create_from_test_cases(self, sample_test_cases: list[Case]) -> None:
        db = DB.from_test_cases(sample_test_cases)
        assert db.number_of_tests > 0
        assert db.hash != ""

    def test_update_blocked_tests(self, sample_db: DB) -> None:
        info = Info(set="owasp", case="xss-scripting", payload="test", encoder="Plain", placeholder="URLParam")
        sample_db.update_blocked_tests(info)
        assert len(sample_db.blocked_tests) == 1
        assert sample_db.counters["owasp"]["xss-scripting"]["blocked"] == 1

    def test_update_passed_tests(self, sample_db: DB) -> None:
        info = Info(set="owasp", case="xss-scripting", payload="test", encoder="Plain", placeholder="URLParam")
        sample_db.update_passed_tests(info)
        assert len(sample_db.passed_tests) == 1
        assert sample_db.counters["owasp"]["xss-scripting"]["passed"] == 1

    def test_get_statistics(self, sample_db: DB) -> None:
        # Add some test results
        info_blocked = Info(set="owasp", case="xss-scripting", payload="<script>", encoder="Plain", placeholder="URLParam")
        info_passed = Info(set="false-pos", case="texts", payload="normal", encoder="Plain", placeholder="URLParam")
        sample_db.update_blocked_tests(info_blocked)
        sample_db.update_passed_tests(info_passed)

        stats = get_statistics(sample_db, ignore_unresolved=False, non_blocked_as_passed=False)
        assert stats.test_cases_fingerprint == sample_db.hash
