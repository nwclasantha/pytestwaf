"""Tests for CSV export module."""

from __future__ import annotations

import csv
import tempfile
from pathlib import Path

import pytest

from gotestwaf.db.database import DB
from gotestwaf.db.export import export_payloads
from gotestwaf.db.models import Case, Info, Placeholder


@pytest.fixture
def db_with_results() -> DB:
    cases = [
        Case(payloads=["<script>"], encoders=["Plain"], placeholders=[Placeholder(name="URLParam")],
             type="XSS", set="owasp", name="xss", is_true_positive=True),
        Case(payloads=["normal"], encoders=["Plain"], placeholders=[Placeholder(name="URLParam")],
             type="FP", set="false-pos", name="texts", is_true_positive=False),
    ]
    db = DB.from_test_cases(cases)
    db.update_blocked_tests(Info(set="owasp", case="xss", payload="<script>", encoder="Plain",
                                 placeholder="URLParam", response_status_code=403))
    db.update_passed_tests(Info(set="false-pos", case="texts", payload="normal", encoder="Plain",
                                placeholder="URLParam", response_status_code=200))
    db.update_na_tests(Info(set="owasp", case="xss", payload="<script>", encoder="URL",
                            placeholder="URLParam", response_status_code=0), False, False, True)
    return db


class TestExportPayloads:
    def test_creates_csv_file(self, db_with_results: DB, tmp_path: Path) -> None:
        out = tmp_path / "payloads.csv"
        export_payloads(db_with_results, str(out))
        assert out.exists()
        assert out.stat().st_size > 0

    def test_csv_header_columns(self, db_with_results: DB, tmp_path: Path) -> None:
        out = tmp_path / "payloads.csv"
        export_payloads(db_with_results, str(out))
        with out.open(newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
        expected = ["Payload", "Check Status", "Response Code", "Placeholder",
                    "Encoder", "Set", "Case", "Test Result"]
        assert header == expected

    def test_csv_row_count(self, db_with_results: DB, tmp_path: Path) -> None:
        out = tmp_path / "payloads.csv"
        export_payloads(db_with_results, str(out))
        with out.open(newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))
        # header + 1 blocked + 1 passed + 1 unresolved = 4
        assert len(rows) == 4

    def test_blocked_test_result(self, db_with_results: DB, tmp_path: Path) -> None:
        out = tmp_path / "payloads.csv"
        export_payloads(db_with_results, str(out))
        with out.open(newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))
        blocked_rows = [r for r in rows[1:] if r[1] == "blocked"]
        assert len(blocked_rows) == 1
        assert blocked_rows[0][7] == "passed"  # blocked attack = passed test

    def test_false_positive_test_result(self, db_with_results: DB, tmp_path: Path) -> None:
        out = tmp_path / "payloads.csv"
        export_payloads(db_with_results, str(out))
        with out.open(newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))
        passed_rows = [r for r in rows[1:] if r[1] == "passed"]
        assert len(passed_rows) == 1
        assert passed_rows[0][7] == "passed"  # passed benign = passed test

    def test_bad_encoder_doesnt_crash(self, tmp_path: Path) -> None:
        cases = [Case(payloads=["p"], encoders=["Plain"], placeholders=[Placeholder(name="URLParam")],
                       set="s", name="n")]
        db = DB.from_test_cases(cases)
        db.blocked_tests.append(Info(set="s", case="n", payload="p", encoder="NonExistent",
                                      placeholder="URLParam", response_status_code=403))
        out = tmp_path / "payloads.csv"
        export_payloads(db, str(out))  # Should not crash
        assert out.exists()
