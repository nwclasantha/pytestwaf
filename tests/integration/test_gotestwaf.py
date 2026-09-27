"""Integration tests for GoTestWAF.

These tests require a running WAF instance. They mirror the Go integration tests
in tests/integration/gotestwaf_test.go.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import pytest

from gotestwaf.config.config import Config
from gotestwaf.db.database import DB
from gotestwaf.db.load import load_test_cases
from gotestwaf.db.statistics import get_statistics
from gotestwaf.scanner.scanner import Scanner


@pytest.fixture
def integration_config() -> Config:
    """Configuration for integration tests."""
    return Config(
        url="http://localhost:8080",
        test_cases_path="testcases",
        block_status_codes=[403],
        pass_status_codes=[200, 404],
        workers=5,
        send_delay=0,
        random_delay=0,
        no_email_report=True,
        skip_waf_identification=True,
    )


@pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION_TESTS", "0") != "1",
    reason="Integration tests require RUN_INTEGRATION_TESTS=1 and a running WAF on localhost:8080",
)
class TestIntegration:
    """Integration test suite mirroring Go's gotestwaf_test.go."""

    def test_load_test_cases(self, integration_config: Config) -> None:
        """Test that test cases can be loaded."""
        cases = load_test_cases(integration_config)
        assert len(cases) > 0

    def test_create_db(self, integration_config: Config) -> None:
        """Test database creation from test cases."""
        cases = load_test_cases(integration_config)
        db = DB.from_test_cases(cases)
        assert db.number_of_tests > 0
        assert db.hash != ""

    @pytest.mark.asyncio
    async def test_scanner_initialization(self, integration_config: Config) -> None:
        """Test that the scanner can be initialized."""
        cases = load_test_cases(integration_config)
        db = DB.from_test_cases(cases)
        scanner = Scanner(integration_config, db)
        await scanner.initialize()

    @pytest.mark.asyncio
    async def test_waf_block_check(self, integration_config: Config) -> None:
        """Test WAF block pre-check."""
        cases = load_test_cases(integration_config)
        db = DB.from_test_cases(cases)
        scanner = Scanner(integration_config, db)
        await scanner.initialize()
        await scanner.waf_block_check()

    @pytest.mark.asyncio
    async def test_full_scan(self, integration_config: Config) -> None:
        """Test a full scan with statistics."""
        cases = load_test_cases(integration_config)
        db = DB.from_test_cases(cases)
        scanner = Scanner(integration_config, db)
        await scanner.initialize()
        await scanner.run()

        stats = get_statistics(db, ignore_unresolved=False, non_blocked_as_passed=False)
        assert stats.true_positive_tests.req_stats.all_requests_number > 0
