"""Parity tests: verify Python encoders produce identical output to Go encoders.

These tests use golden fixtures generated from the Go implementation.
When the Go binary is available, they can be run against both implementations
to assert byte-for-byte identical outputs for deterministic operations.
"""

from __future__ import annotations

import pytest

from gotestwaf.payload.encoder.encoder import apply_encoder

# Golden test vectors generated from Go implementation
GOLDEN_VECTORS = [
    # (encoder_name, input, expected_output)
    ("Base64", "hello", "aGVsbG8="),
    ("Base64", "", ""),
    ("Base64", "<script>alert(1)</script>", "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="),
    ("Base64Flat", "hello", "aGVsbG8"),
    ("Base64Flat", "test==", "dGVzdD09"),
    ("Plain", "hello world", "hello world"),
    ("Plain", "<script>", "<script>"),
    ("Plain", "", ""),
    ("URL", "hello world", "hello%20world"),
    ("URL", "/path/to/file", "%2Fpath%2Fto%2Ffile"),
    ("URL", "a=b&c=d", "a=b&c=d"),
    ("JSUnicode", "AB", "\\u0041\\u0042"),
    ("JSUnicode", "<>", "\\u003c\\u003e"),
    ("XMLEntity", "<script>", "<string>&lt;script&gt;</string>\n"),
    ("XMLEntity", "a&b", "<string>a&amp;b</string>\n"),
    ("XMLEntity", '"quotes"', '<string>"quotes"</string>\n'),
]


@pytest.mark.parametrize(
    "encoder_name,input_data,expected",
    GOLDEN_VECTORS,
    ids=[f"{v[0]}({v[1][:20]})" for v in GOLDEN_VECTORS],
)
def test_encoder_parity(encoder_name: str, input_data: str, expected: str) -> None:
    """Verify Python encoder output matches Go encoder output."""
    result = apply_encoder(encoder_name, input_data)
    assert result == expected, (
        f"Parity failure for {encoder_name}({input_data!r}): "
        f"got {result!r}, expected {expected!r}"
    )
