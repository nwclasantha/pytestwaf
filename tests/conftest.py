"""Shared test fixtures for GoTestWAF tests."""

from __future__ import annotations

import pytest

from gotestwaf.config.config import Config
from gotestwaf.db.database import DB
from gotestwaf.db.models import Case, Placeholder


@pytest.fixture
def sample_config() -> Config:
    """Create a sample configuration for testing."""
    return Config(
        url="http://localhost:8080",
        test_cases_path="testcases",
        block_status_codes=[403],
        pass_status_codes=[200, 404],
        workers=5,
        send_delay=0,
        random_delay=0,
    )


@pytest.fixture
def sample_test_cases() -> list[Case]:
    """Create sample test cases."""
    return [
        Case(
            payloads=["<script>alert(1)</script>"],
            encoders=["Plain"],
            placeholders=[Placeholder(name="URLParam")],
            type="XSS",
            set="owasp",
            name="xss-scripting",
            is_true_positive=True,
        ),
        Case(
            payloads=["' OR 1=1 --"],
            encoders=["Plain", "URL"],
            placeholders=[Placeholder(name="URLParam"), Placeholder(name="Header")],
            type="SQL Injection",
            set="owasp",
            name="sql-injection",
            is_true_positive=True,
        ),
        Case(
            payloads=["normal text"],
            encoders=["Plain"],
            placeholders=[Placeholder(name="URLParam")],
            type="False Positive",
            set="false-pos",
            name="texts",
            is_true_positive=False,
        ),
    ]


@pytest.fixture
def sample_db(sample_test_cases: list[Case]) -> DB:
    """Create a sample database from test cases."""
    return DB.from_test_cases(sample_test_cases)
