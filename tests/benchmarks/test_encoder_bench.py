"""Benchmark tests for payload encoders.

Mirrors Go's testing.B benchmarks using pytest-benchmark.
"""

from __future__ import annotations

import pytest

from gotestwaf.payload.encoder.encoder import apply_encoder


@pytest.fixture(params=["Base64", "Base64Flat", "JSUnicode", "Plain", "URL", "XMLEntity"])
def encoder_name(request: pytest.FixtureRequest) -> str:
    return request.param


SAMPLE_PAYLOAD = "<script>alert('XSS')</script>"
LARGE_PAYLOAD = "A" * 10000


def test_encode_short_payload(benchmark: object, encoder_name: str) -> None:
    """Benchmark encoding a short payload."""
    benchmark(apply_encoder, encoder_name, SAMPLE_PAYLOAD)  # type: ignore[operator]


def test_encode_large_payload(benchmark: object, encoder_name: str) -> None:
    """Benchmark encoding a large payload."""
    benchmark(apply_encoder, encoder_name, LARGE_PAYLOAD)  # type: ignore[operator]
