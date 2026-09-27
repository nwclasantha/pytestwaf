"""Helper functions for database operations."""

from __future__ import annotations

import math


def round_value(n: float) -> float:
    """Round a float to 2 decimal places, treating NaN as 0.0.

    Uses round-half-away-from-zero to match Go's math.Round behavior.
    """
    if math.isnan(n):
        return 0.0
    if math.isinf(n):
        return 0.0
    try:
        return math.floor(n * 100 + 0.5) / 100
    except (OverflowError, ValueError):
        return 0.0


def calculate_percentage(first: int | float, second: int | float) -> float:
    """Calculate percentage of first/second, returning 0.0 for division by zero or NaN."""
    if second == 0:
        return 0.0
    result = float(first) / float(second) * 100
    if math.isnan(result):
        return 0.0
    return round_value(result)


def is_false_positive_test(set_name: str) -> bool:
    """Check if a test set is a false positive test."""
    return "false" in set_name


def is_api_test(set_name: str) -> bool:
    """Check if a test set is an API test."""
    return "api" in set_name
