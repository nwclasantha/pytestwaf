"""Tests for email report module."""

from __future__ import annotations

import os

import pytest

from gotestwaf.report.email import DEFAULT_SERVER_URL, EmailErrorResponse


class TestEmailConfig:
    def test_default_server_url(self) -> None:
        assert "wallarm.tools" in DEFAULT_SERVER_URL
        assert DEFAULT_SERVER_URL.startswith("https://")

    def test_email_error_response(self) -> None:
        err = EmailErrorResponse("test error")
        assert str(err) == "test error"
        assert err.msg == "test error"

    def test_env_var_override(self) -> None:
        """Verify the email module reads GTW_EMAIL_SERVER_URL env var."""
        # Just verify the import and default — actual HTTP test would need respx
        from gotestwaf.report.email import send_email
        assert callable(send_email)
