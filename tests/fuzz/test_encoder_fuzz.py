"""Fuzz tests for payload encoders using hypothesis.

Mirrors Go's testing/fuzz tests.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from gotestwaf.payload.encoder.encoder import apply_encoder


@given(data=st.text(min_size=0, max_size=10000))
@settings(max_examples=500)
def test_fuzz_base64_encoder(data: str) -> None:
    """Fuzz Base64 encoder - must never crash."""
    result = apply_encoder("Base64", data)
    assert isinstance(result, str)
    assert len(result) >= 0


@given(data=st.text(min_size=0, max_size=10000))
@settings(max_examples=500)
def test_fuzz_base64flat_encoder(data: str) -> None:
    """Fuzz Base64Flat encoder - must never crash and must not contain '='."""
    result = apply_encoder("Base64Flat", data)
    assert isinstance(result, str)
    assert "=" not in result


@given(data=st.text(min_size=0, max_size=5000))
@settings(max_examples=500)
def test_fuzz_jsunicode_encoder(data: str) -> None:
    """Fuzz JSUnicode encoder - result must be valid unicode escapes."""
    result = apply_encoder("JSUnicode", data)
    assert isinstance(result, str)
    if data:
        assert "\\u" in result


@given(data=st.text(min_size=0, max_size=10000))
@settings(max_examples=500)
def test_fuzz_url_encoder(data: str) -> None:
    """Fuzz URL encoder - must never crash."""
    result = apply_encoder("URL", data)
    assert isinstance(result, str)


@given(data=st.text(min_size=0, max_size=10000))
@settings(max_examples=500)
def test_fuzz_xmlentity_encoder(data: str) -> None:
    """Fuzz XMLEntity encoder - must escape angle brackets."""
    result = apply_encoder("XMLEntity", data)
    assert isinstance(result, str)
    # Raw < and > should be escaped
    if "<" in data:
        assert "&lt;" in result
    if ">" in data:
        assert "&gt;" in result


@given(data=st.text(min_size=0, max_size=10000))
@settings(max_examples=500)
def test_fuzz_plain_encoder(data: str) -> None:
    """Fuzz Plain encoder - must return input unchanged."""
    result = apply_encoder("Plain", data)
    assert result == data
