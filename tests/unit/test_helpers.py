"""Tests for helper utilities."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from gotestwaf.helpers.email import validate_email
from gotestwaf.helpers.file_move import file_move
from gotestwaf.helpers.url import get_target_url_str, host_port_from_url
from gotestwaf.helpers.utils import deep_copy_map


class TestValidateEmail:
    def test_valid_email(self) -> None:
        result = validate_email("test@example.com")
        assert result == "test@example.com"

    def test_invalid_email(self) -> None:
        from gotestwaf.errors import ValidationError
        with pytest.raises(ValidationError):
            validate_email("not-an-email")


class TestFileMove:
    def test_move_file(self, tmp_path: Path) -> None:
        src = tmp_path / "source.txt"
        dst = tmp_path / "dest.txt"
        src.write_text("hello")

        file_move(str(src), str(dst))

        assert not src.exists()
        assert dst.read_text() == "hello"

    def test_same_file_raises(self, tmp_path: Path) -> None:
        src = tmp_path / "file.txt"
        src.write_text("hello")

        with pytest.raises(ValueError, match="same"):
            file_move(str(src), str(src))


class TestURLHelpers:
    def test_get_target_url_str(self) -> None:
        result = get_target_url_str("http://example.com/path?query=1#frag")
        assert result == "http://example.com"

    def test_host_port_from_url(self) -> None:
        is_tls, host_port = host_port_from_url("http://example.com:8080", 9000)
        assert is_tls is False
        assert host_port == "example.com:9000"

    def test_host_port_from_https_url(self) -> None:
        is_tls, host_port = host_port_from_url("https://example.com", 443)
        assert is_tls is True
        assert host_port == "example.com:443"


class TestDeepCopyMap:
    def test_copy_is_independent(self) -> None:
        original = {"a": "1", "b": "2"}
        copy = deep_copy_map(original)
        copy["c"] = "3"
        assert "c" not in original
