"""Standard HTTP client implementation using httpx (async)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import structlog

from gotestwaf.config.config import Config
from gotestwaf.helpers.utils import deep_copy_map
from gotestwaf.payload.payload import PayloadInfo
from gotestwaf.payload.placeholder.useragent import UA_HEADER
from gotestwaf.scanner.clients import GTW_DEBUG_HEADER
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest, Request
from gotestwaf.scanner.types.response import Response, ResponseMeta

GET_COOKIES_REPEAT_ATTEMPTS = 3
SESSION_COOKIES_FILE = "session_cookies.json"

_logger = structlog.get_logger()


def _load_session_cookies() -> dict[str, str]:
    """Load session cookies from file if it exists.

    These cookies are harvested by harvest_cookies.py to bypass
    CAPTCHA/bot protection for authorized security testing.
    """
    path = Path(SESSION_COOKIES_FILE)
    if not path.exists():
        return {}

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        cookies: dict[str, str] = {}
        for c in raw:
            if isinstance(c, dict) and "name" in c and "value" in c:
                cookies[c["name"]] = c["value"]
        if cookies:
            _logger.info(
                "Loaded session cookies for CAPTCHA bypass",
                count=len(cookies),
                file=SESSION_COOKIES_FILE,
            )
        return cookies
    except Exception as e:
        _logger.warning("Failed to load session cookies", error=str(e))
        return {}


class Client:
    """Async HTTP client wrapping httpx for sending payloads and requests."""

    def __init__(self, cfg: Config) -> None:
        self._headers = deep_copy_map(cfg.http_headers)
        custom_header_parts = cfg.add_header.split(":", 1)
        if len(custom_header_parts) > 1:
            self._headers[custom_header_parts[0].strip()] = custom_header_parts[1].strip()

        self._host_header = self._headers.get("Host", "")
        self._follow_cookies = cfg.follow_cookies
        self._renew_session = cfg.renew_session
        self._verify_ssl = cfg.tls_verify
        self._max_redirects = cfg.max_redirects
        self._proxy = cfg.proxy or None
        self._idle_conn_timeout = cfg.idle_conn_timeout
        self._max_idle_conns = cfg.max_idle_conns
        self._session_cookies: dict[str, str] | None = None  # Loaded lazily on first request

        self._client: httpx.AsyncClient | None = None

    def _get_session_cookies(self) -> dict[str, str]:
        """Get session cookies, loading from file on first access."""
        if self._session_cookies is None:
            self._session_cookies = _load_session_cookies()
        return self._session_cookies

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=self._verify_ssl,
                follow_redirects=self._max_redirects > 0,
                max_redirects=self._max_redirects,
                timeout=httpx.Timeout(30.0, connect=10.0),
                proxy=self._proxy,
            )
        return self._client

    async def send_payload(self, target_url: str, payload_info: PayloadInfo) -> Response:
        """Send a payload to the target URL.

        Args:
            target_url: The target URL.
            payload_info: Payload information.

        Returns:
            Response from the server.
        """
        request = payload_info.get_request(target_url, HTTPClientType.GO_HTTP_CLIENT)

        if not isinstance(request, GoHTTPRequest):
            msg = f"bad request type: {type(request).__name__}, expected GoHTTPRequest"
            raise TypeError(msg)

        # Apply configured headers (case-insensitive check, matching Go's http.Header.Get)
        is_ua_placeholder = payload_info.placeholder_name == "UserAgent"
        headers = dict(request.headers)
        existing_headers_lower = {k.lower() for k in headers}
        for header, value in self._headers.items():
            if header.lower() == UA_HEADER.lower() and is_ua_placeholder:
                continue
            # Do not replace header values for RawRequest headers (case-insensitive)
            if header.lower() not in existing_headers_lower:
                headers[header] = value

        # Set Host header (mirrors Go's req.Host)
        if self._host_header:
            headers["Host"] = self._host_header

        if payload_info.debug_header_value:
            headers[GTW_DEBUG_HEADER] = payload_info.debug_header_value

        # Build cookies: session cookies + follow cookies + renew cookies
        cookies: dict[str, str] = dict(self._get_session_cookies())
        if self._follow_cookies and self._renew_session:
            renewed = await self._get_cookies(target_url)
            cookies.update(renewed)

        # Set cookies directly in Cookie header (not as httpx cookies dict)
        # This bypasses httpx's domain matching which drops cookies without domain info
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            if "Cookie" in headers:
                headers["Cookie"] = headers["Cookie"] + "; " + cookie_str
            else:
                headers["Cookie"] = cookie_str

        client = await self._get_client()

        content: bytes | None = None
        if isinstance(request.content, str):
            content = request.content.encode("utf-8")
        elif isinstance(request.content, bytes):
            content = request.content

        resp = await client.request(
            method=request.method,
            url=request.url,
            headers=headers,
            content=content,
        )

        # Build multi-value header dict
        send_resp_headers: dict[str, list[str]] = {}
        for key, value in resp.headers.multi_items():
            send_resp_headers.setdefault(key, []).append(value)

        return ResponseMeta(
            status_code=resp.status_code,
            status_reason=resp.reason_phrase or "",
            headers=send_resp_headers,
            content=resp.content,
        )

    async def send_request(self, req: Request) -> Response:
        """Send a prepared request.

        Args:
            req: The request to send.

        Returns:
            Response from the server.
        """
        if not isinstance(req, GoHTTPRequest):
            msg = f"bad request type: {type(req).__name__}, expected GoHTTPRequest"
            raise TypeError(msg)

        headers = dict(self._headers)
        # Request-specific headers take precedence over client defaults
        headers.update(req.headers)

        if req.debug_header_value:
            headers[GTW_DEBUG_HEADER] = req.debug_header_value

        cookies: dict[str, str] = dict(self._get_session_cookies())
        if self._follow_cookies and self._renew_session:
            from urllib.parse import urlparse
            parsed = urlparse(req.url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            renewed = await self._get_cookies(base_url)
            cookies.update(renewed)

        # Set cookies directly in Cookie header (bypasses httpx domain matching)
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            if "Cookie" in headers:
                headers["Cookie"] = headers["Cookie"] + "; " + cookie_str
            else:
                headers["Cookie"] = cookie_str

        client = await self._get_client()

        content: bytes | None = None
        if isinstance(req.content, str):
            content = req.content.encode("utf-8")
        elif isinstance(req.content, bytes):
            content = req.content

        resp = await client.request(
            method=req.method,
            url=req.url,
            headers=headers,
            content=content,
        )

        # Build multi-value header dict
        resp_headers: dict[str, list[str]] = {}
        for key, value in resp.headers.multi_items():
            resp_headers.setdefault(key, []).append(value)

        return ResponseMeta(
            status_code=resp.status_code,
            status_reason=resp.reason_phrase or "",
            headers=resp_headers,
            content=resp.content,
        )

    async def _get_cookies(self, target_url: str) -> dict[str, str]:
        """Get cookies by making a GET request to the target.

        Args:
            target_url: URL to request cookies from.

        Returns:
            Dictionary of cookie name -> value.
        """
        last_error: Exception | None = None

        # Reuse the long-lived `_client` so cookie refreshes don't open a fresh
        # connection pool + TLS handshake on every request — with hundreds of
        # payloads under --renewSession that adds up to a substantial latency
        # tax and breaks HTTP/2 connection coalescing for the same host.
        for _ in range(GET_COOKIES_REPEAT_ATTEMPTS):
            try:
                client = await self._get_client()
                cookie_headers = dict(self._headers)
                if self._host_header:
                    cookie_headers["Host"] = self._host_header
                # Add session cookies to header for this request too
                session_cookies = self._get_session_cookies()
                if session_cookies:
                    ck = "; ".join(f"{k}={v}" for k, v in session_cookies.items())
                    cookie_headers["Cookie"] = ck
                resp = await client.get(target_url, headers=cookie_headers)
                # Parse cookies from raw Set-Cookie headers (avoids domain filtering)
                cookies: dict[str, str] = {}
                for hdr_val in resp.headers.get_list("set-cookie"):
                    name_val = hdr_val.split(";")[0].strip()
                    if "=" in name_val:
                        k, v = name_val.split("=", 1)
                        cookies[k.strip()] = v.strip()
                return cookies
            except Exception as e:
                last_error = e
                continue

        if last_error:
            msg = f"couldn't get cookies: {last_error}"
            raise RuntimeError(msg) from last_error
        return {}

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
