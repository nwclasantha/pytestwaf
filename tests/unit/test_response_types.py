"""Tests for scanner type definitions — response, request, client types."""

from __future__ import annotations

import pytest

from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import ChromeDPTasks, GoHTTPRequest
from gotestwaf.scanner.types.response import GoHTTPResponse, ResponseMeta


class TestHTTPClientType:
    def test_go_http_str(self) -> None:
        assert str(HTTPClientType.GO_HTTP_CLIENT) == "GoHTTPClient"

    def test_chrome_str(self) -> None:
        assert str(HTTPClientType.CHROME_HTTP_CLIENT) == "ChromeHTTPClient"

    def test_values(self) -> None:
        assert HTTPClientType.GO_HTTP_CLIENT == 0
        assert HTTPClientType.CHROME_HTTP_CLIENT == 1


class TestGoHTTPRequest:
    def test_default_values(self) -> None:
        req = GoHTTPRequest()
        assert req.method == "GET"
        assert req.url == ""
        assert req.headers == {}
        assert req.content is None
        assert req.debug_header_value == ""

    def test_is_request(self) -> None:
        req = GoHTTPRequest()
        req.is_request()  # Should not raise

    def test_custom_values(self) -> None:
        req = GoHTTPRequest(method="POST", url="http://test.com", headers={"X-Test": "1"}, content="body")
        assert req.method == "POST"
        assert req.url == "http://test.com"
        assert req.headers["X-Test"] == "1"
        assert req.content == "body"


class TestChromeDPTasks:
    def test_default_values(self) -> None:
        tasks = ChromeDPTasks()
        assert tasks.tasks == []
        assert tasks.debug_header_value == ""

    def test_is_request(self) -> None:
        tasks = ChromeDPTasks()
        tasks.is_request()  # Should not raise


class TestResponseMeta:
    def test_default_values(self) -> None:
        resp = ResponseMeta()
        assert resp.get_status_code() == 0
        assert resp.get_reason() == ""
        assert resp.get_headers() == {}
        assert resp.get_content() == b""
        assert resp.get_error() is None

    def test_with_error(self) -> None:
        resp = ResponseMeta(error="something failed")
        err = resp.get_error()
        assert err is not None
        assert "something failed" in str(err)

    def test_with_data(self) -> None:
        resp = ResponseMeta(
            status_code=403,
            status_reason="Forbidden",
            headers={"Server": ["nginx"]},
            content=b"Access Denied",
        )
        assert resp.get_status_code() == 403
        assert resp.get_reason() == "Forbidden"
        assert resp.get_headers()["Server"] == ["nginx"]
        assert resp.get_content() == b"Access Denied"
