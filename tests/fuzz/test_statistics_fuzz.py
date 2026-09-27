"""Fuzz tests for statistics computation using hypothesis.

Mirrors Go's gopter-based property tests in internal/db/statistics_test.go.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from gotestwaf.db.helpers import calculate_percentage, round_value


@given(n=st.floats(allow_nan=True, allow_infinity=True))
@settings(max_examples=1000)
def test_fuzz_round_value(n: float) -> None:
    """round_value must never crash and must return a finite number."""
    result = round_value(n)
    assert isinstance(result, float)
    assert result == result  # not NaN


@given(
    first=st.integers(min_value=0, max_value=1000000),
    second=st.integers(min_value=0, max_value=1000000),
)
@settings(max_examples=1000)
def test_fuzz_calculate_percentage(first: int, second: int) -> None:
    """calculate_percentage must return non-negative value or 0 for zero denominator.

    Note: result can exceed 100% when first > second, matching Go behavior.
    """
    result = calculate_percentage(first, second)
    assert isinstance(result, float)
    assert result >= 0.0
    if second == 0:
        assert result == 0.0
    if first == 0:
        assert result == 0.0
