"""Tests for payload placeholders."""

from __future__ import annotations

import pytest

from gotestwaf.payload.placeholder.header import HeaderPlaceholder
from gotestwaf.payload.placeholder.urlparam import URLParamPlaceholder
from gotestwaf.payload.placeholder.urlpath import URLPathPlaceholder
from gotestwaf.payload.placeholder.useragent import UserAgentPlaceholder
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest


class TestURLParamPlaceholder:
    @pytest.mark.parametrize(
        "url,payload,expected_contains",
        [
            ("http://example.com", "test", "?"),
            ("http://example.com/path", "payload", "?"),
            ("http://example.com/path?existing=1", "new", "&"),
        ],
        ids=["base-url", "with-path", "existing-query"],
    )
    def test_creates_request_with_param(self, url: str, payload: str, expected_contains: str) -> None:
        ph = URLParamPlaceholder()
        req = ph.create_request(url, payload, None, HTTPClientType.GO_HTTP_CLIENT)
        assert isinstance(req, GoHTTPRequest)
        assert expected_contains in req.url
        assert payload in req.url


class TestURLPathPlaceholder:
    @pytest.mark.parametrize(
        "url,payload",
        [
            ("http://example.com", "test"),
            ("http://example.com/", "payload"),
            ("http://example.com/base/", "path-payload"),
        ],
        ids=["no-slash", "with-slash", "with-path"],
    )
    def test_creates_request_with_path(self, url: str, payload: str) -> None:
        ph = URLPathPlaceholder()
        req = ph.create_request(url, payload, None, HTTPClientType.GO_HTTP_CLIENT)
        assert isinstance(req, GoHTTPRequest)
        assert payload in req.url


class TestUserAgentPlaceholder:
    def test_sets_user_agent_header(self) -> None:
        ph = UserAgentPlaceholder()
        req = ph.create_request("http://example.com", "custom-ua", None, HTTPClientType.GO_HTTP_CLIENT)
        assert isinstance(req, GoHTTPRequest)
        assert req.headers.get("User-Agent") == "custom-ua"


class TestHeaderPlaceholder:
    def test_sets_random_header(self) -> None:
        ph = HeaderPlaceholder()
        req = ph.create_request("http://example.com", "header-payload", None, HTTPClientType.GO_HTTP_CLIENT)
        assert isinstance(req, GoHTTPRequest)
        # Should have a header starting with X-
        x_headers = {k: v for k, v in req.headers.items() if k.startswith("X-")}
        assert len(x_headers) == 1
        assert list(x_headers.values())[0] == "header-payload"
