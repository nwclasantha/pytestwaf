"""Unit tests for scanner module — blocked/passed detection, test production, DB updates."""

from __future__ import annotations

import pytest

from gotestwaf.config.config import Config
from gotestwaf.db.database import DB
from gotestwaf.db.models import Case, Info, Placeholder
from gotestwaf.scanner.scanner import PayloadConfig, Scanner, TestStatus
from gotestwaf.scanner.types.response import ResponseMeta


@pytest.fixture
def cfg() -> Config:
    return Config(
        url="http://localhost:8080",
        block_status_codes=[403],
        pass_status_codes=[200, 404],
        workers=1,
        send_delay=0,
        random_delay=0,
    )


@pytest.fixture
def db_with_cases() -> DB:
    cases = [
        Case(
            payloads=["<script>alert(1)</script>"],
            encoders=["Plain"],
            placeholders=[Placeholder(name="URLParam")],
            type="XSS",
            set="owasp",
            name="xss",
            is_true_positive=True,
        ),
    ]
    return DB.from_test_cases(cases)


class TestCheckBlockedOrPassed:
    """Test the _check_blocked_or_passed logic."""

    def test_blocked_by_status_code(self, cfg: Config, db_with_cases: DB) -> None:
        scanner = Scanner(cfg, db_with_cases)
        resp = ResponseMeta(status_code=403, content=b"Forbidden")
        blocked, passed = scanner._check_blocked_or_passed(resp)
        assert blocked is True

    def test_passed_by_status_code(self, cfg: Config, db_with_cases: DB) -> None:
        scanner = Scanner(cfg, db_with_cases)
        resp = ResponseMeta(status_code=200, content=b"OK")
        blocked, passed = scanner._check_blocked_or_passed(resp)
        assert passed is True
        assert blocked is False

    def test_both_blocked_and_passed(self, cfg: Config, db_with_cases: DB) -> None:
        """Status 403 is in block list AND pass list — should be both True."""
        cfg.pass_status_codes = [403]
        scanner = Scanner(cfg, db_with_cases)
        resp = ResponseMeta(status_code=403, content=b"")
        blocked, passed = scanner._check_blocked_or_passed(resp)
        assert blocked is True
        assert passed is True

    def test_neither_blocked_nor_passed(self, cfg: Config, db_with_cases: DB) -> None:
        scanner = Scanner(cfg, db_with_cases)
        resp = ResponseMeta(status_code=500, content=b"Error")
        blocked, passed = scanner._check_blocked_or_passed(resp)
        assert blocked is False
        assert passed is False

    def test_block_regex_in_body(self, cfg: Config, db_with_cases: DB) -> None:
        cfg.block_regex = "Access Denied"
        cfg.block_status_codes = []
        scanner = Scanner(cfg, db_with_cases)
        resp = ResponseMeta(status_code=200, content=b"<h1>Access Denied</h1>")
        blocked, passed = scanner._check_blocked_or_passed(resp)
        assert blocked is True

    def test_block_regex_in_header(self, cfg: Config, db_with_cases: DB) -> None:
        cfg.block_regex = "WAF-Block"
        cfg.block_status_codes = []
        scanner = Scanner(cfg, db_with_cases)
        resp = ResponseMeta(
            status_code=200,
            headers={"X-WAF": ["WAF-Block-123"]},
            content=b"OK",
        )
        blocked, passed = scanner._check_blocked_or_passed(resp)
        assert blocked is True

    def test_pass_regex_in_body(self, cfg: Config, db_with_cases: DB) -> None:
        cfg.pass_regex = "Welcome"
        cfg.pass_status_codes = []
        scanner = Scanner(cfg, db_with_cases)
        resp = ResponseMeta(status_code=200, content=b"Welcome to the app")
        blocked, passed = scanner._check_blocked_or_passed(resp)
        assert passed is True

    def test_check_block_func(self, cfg: Config, db_with_cases: DB) -> None:
        """Custom check_block_func from WAF detector."""
        cfg.check_block_func = lambda resps: True
        cfg.block_status_codes = []
        scanner = Scanner(cfg, db_with_cases)
        resp = ResponseMeta(status_code=200, content=b"OK")
        blocked, passed = scanner._check_blocked_or_passed(resp)
        assert blocked is True
        assert passed is False


class TestProduceTests:
    """Test payload configuration generation."""

    def test_produces_correct_count(self, cfg: Config) -> None:
        cases = [
            Case(
                payloads=["p1", "p2"],
                encoders=["Plain", "URL"],
                placeholders=[Placeholder(name="URLParam"), Placeholder(name="Header")],
                type="XSS",
                set="owasp",
                name="xss",
                is_true_positive=True,
            ),
        ]
        db = DB.from_test_cases(cases)
        scanner = Scanner(cfg, db)
        configs = scanner._produce_tests()
        # 2 payloads * 2 encoders * 2 placeholders = 8
        assert len(configs) == 8

    def test_debug_header_enabled(self, cfg: Config) -> None:
        cases = [
            Case(
                payloads=["p1"],
                encoders=["Plain"],
                placeholders=[Placeholder(name="URLParam")],
                type="XSS",
                set="owasp",
                name="xss",
                is_true_positive=True,
            ),
        ]
        db = DB.from_test_cases(cases)
        scanner = Scanner(cfg, db, enable_debug_header=True)
        configs = scanner._produce_tests()
        assert len(configs) == 1
        assert configs[0].debug_header_value != ""
        assert len(configs[0].debug_header_value) == 64  # SHA256 hex

    def test_debug_header_disabled(self, cfg: Config) -> None:
        cases = [
            Case(
                payloads=["p1"],
                encoders=["Plain"],
                placeholders=[Placeholder(name="URLParam")],
                type="XSS",
                set="owasp",
                name="xss",
                is_true_positive=True,
            ),
        ]
        db = DB.from_test_cases(cases)
        scanner = Scanner(cfg, db, enable_debug_header=False)
        configs = scanner._produce_tests()
        assert configs[0].debug_header_value == ""


class TestUpdateDB:
    """Test _update_db logic for classifying results."""

    def _make_pc(self) -> PayloadConfig:
        return PayloadConfig(
            payload="<script>",
            encoder="Plain",
            placeholder=Placeholder(name="URLParam"),
            set_name="owasp",
            case_name="xss",
            test_type="XSS",
            is_true_positive=True,
            debug_header_value="",
        )

    def test_blocked_response(self, cfg: Config, db_with_cases: DB) -> None:
        scanner = Scanner(cfg, db_with_cases)
        pc = self._make_pc()
        ts = TestStatus()
        resp = ResponseMeta(status_code=403, content=b"Blocked")
        scanner._update_db(pc, ts, None, resp, None, "")
        assert ts.blocked_test is not None
        assert db_with_cases.counters["owasp"]["xss"]["blocked"] == 1

    def test_passed_response(self, cfg: Config, db_with_cases: DB) -> None:
        scanner = Scanner(cfg, db_with_cases)
        pc = self._make_pc()
        ts = TestStatus()
        resp = ResponseMeta(status_code=200, content=b"OK")
        scanner._update_db(pc, ts, None, resp, None, "")
        assert ts.passed_test is not None
        assert db_with_cases.counters["owasp"]["xss"]["passed"] == 1

    def test_unresolved_response(self, cfg: Config, db_with_cases: DB) -> None:
        """Status 500: neither blocked nor passed → unresolved."""
        scanner = Scanner(cfg, db_with_cases)
        pc = self._make_pc()
        ts = TestStatus()
        resp = ResponseMeta(status_code=500, content=b"Error")
        scanner._update_db(pc, ts, None, resp, None, "")
        assert ts.unresolved_test is not None

    def test_send_error_marks_failed(self, cfg: Config, db_with_cases: DB) -> None:
        scanner = Scanner(cfg, db_with_cases)
        pc = self._make_pc()
        ts = TestStatus()
        scanner._update_db(pc, ts, None, None, ValueError("timeout"), "")
        assert ts.failed_test is not None
        assert db_with_cases.counters["owasp"]["xss"]["failed"] == 1

    def test_conn_reset_without_block_flag(self, cfg: Config, db_with_cases: DB) -> None:
        """Connection reset without block_conn_reset → unresolved."""
        scanner = Scanner(cfg, db_with_cases)
        pc = self._make_pc()
        ts = TestStatus()
        scanner._update_db(pc, ts, None, None, ConnectionResetError(), "")
        assert ts.unresolved_test is not None

    def test_conn_reset_with_block_flag(self, cfg: Config, db_with_cases: DB) -> None:
        """Connection reset with block_conn_reset → blocked."""
        cfg.block_conn_reset = True
        scanner = Scanner(cfg, db_with_cases)
        pc = self._make_pc()
        ts = TestStatus()
        scanner._update_db(pc, ts, None, None, ConnectionResetError(), "")
        assert ts.blocked_test is not None
