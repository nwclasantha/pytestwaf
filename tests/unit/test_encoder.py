"""Tests for payload encoders."""

from __future__ import annotations

import pytest

from gotestwaf.errors import UnknownEncoderError
from gotestwaf.payload.encoder.encoder import apply_encoder


class TestBase64Encoder:
    def test_base64_normal(self) -> None:
        result = apply_encoder("Base64", "hello")
        assert result == "aGVsbG8="

    def test_base64_flat_no_padding(self) -> None:
        result = apply_encoder("Base64Flat", "hello")
        assert result == "aGVsbG8"

    def test_base64_empty(self) -> None:
        result = apply_encoder("Base64", "")
        assert result == ""


class TestJSUnicodeEncoder:
    def test_encode_ascii(self) -> None:
        result = apply_encoder("JSUnicode", "AB")
        assert result == "\\u0041\\u0042"

    def test_encode_special(self) -> None:
        result = apply_encoder("JSUnicode", "<>")
        assert "\\u003c\\u003e" in result


class TestPlainEncoder:
    def test_passthrough(self) -> None:
        result = apply_encoder("Plain", "test payload")
        assert result == "test payload"


class TestURLEncoder:
    def test_encode_special_chars(self) -> None:
        result = apply_encoder("URL", "hello world")
        assert result == "hello%20world"

    def test_encode_slashes(self) -> None:
        result = apply_encoder("URL", "/path/to/file")
        assert "%2F" in result


class TestXMLEntityEncoder:
    def test_encode_angle_brackets(self) -> None:
        result = apply_encoder("XMLEntity", "<script>")
        assert "&lt;" in result
        assert "&gt;" in result

    def test_encode_ampersand(self) -> None:
        result = apply_encoder("XMLEntity", "a&b")
        assert "&amp;" in result


class TestUnknownEncoder:
    def test_unknown_encoder_raises(self) -> None:
        with pytest.raises(UnknownEncoderError, match="unknown encoder: FooBar"):
            apply_encoder("FooBar", "test")
