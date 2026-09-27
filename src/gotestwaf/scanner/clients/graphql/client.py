"""GraphQL client for sending payloads via HTTP to GraphQL endpoints."""

from __future__ import annotations

from urllib.parse import urlencode, urlparse, urlunparse

import httpx
import orjson

from gotestwaf.config.config import Config
from gotestwaf.helpers.utils import deep_copy_map
from gotestwaf.payload.payload import PayloadInfo
from gotestwaf.payload.placeholder.useragent import UA_HEADER
from gotestwaf.scanner.clients import GTW_DEBUG_HEADER
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest
from gotestwaf.scanner.types.response import Response, ResponseMeta

CHECK_AVAILABILITY_ENDPOINTS = [
    "/graphql",
    "/_graphql",
    "/api/graphql",
    "/GraphQL",
]


class Client:
    """Async GraphQL client for WAF testing."""

    def __init__(self, cfg: Config) -> None:
        self._headers = deep_copy_map(cfg.http_headers)
        custom_header_parts = cfg.add_header.split(":", 1)
        if len(custom_header_parts) > 1:
            self._headers[custom_header_parts[0].strip()] = custom_header_parts[1].strip()

        self._host_header = self._headers.get("Host", "")
        self._graphql_url = cfg.graphql_url
        self._http_url = cfg.url
        self._is_graphql_available = True
        self._verify_ssl = cfg.tls_verify
        self._max_redirects = cfg.max_redirects
        self._proxy = cfg.proxy or None
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the persistent async HTTP client.

        Previously every send_payload / availability call created and tore
        down its own AsyncClient — N TLS handshakes for N payloads — and
        silently ignored `cfg.proxy`. The persistent client honors the
        configured proxy and reuses connections.
        """
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=self._verify_ssl,
                follow_redirects=True,
                timeout=30.0,
                proxy=self._proxy,
            )
        return self._client

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def check_availability(self) -> bool:
        """Check if a GraphQL endpoint is available.

        Returns:
            True if a GraphQL endpoint was found.
        """
        self._is_graphql_available = False

        parsed = urlparse(self._graphql_url)
        endpoints_to_check = CHECK_AVAILABILITY_ENDPOINTS

        if self._graphql_url != self._http_url:
            endpoints_to_check = [parsed.path]

        client = await self._get_client()
        for endpoint in endpoints_to_check:
            query = urlencode({"query": "{__typename}"})
            url = urlunparse((parsed.scheme, parsed.netloc, endpoint, "", query, ""))

            try:
                resp = await client.get(url, headers=self._headers)
                if resp.status_code == 200:
                    ok = _check_answer(resp.content)
                    if ok:
                        clean_url = urlunparse((parsed.scheme, parsed.netloc, endpoint, "", "", ""))
                        self._graphql_url = clean_url
                        self._is_graphql_available = True
                        return True
            except Exception:
                continue

        return False

    def is_available(self) -> bool:
        """Return current availability status."""
        return self._is_graphql_available

    async def send_payload(self, payload_info: PayloadInfo) -> Response:
        """Send a payload to the GraphQL endpoint.

        Args:
            payload_info: The payload to send.

        Returns:
            Response from the server.
        """
        request = payload_info.get_request(self._graphql_url, HTTPClientType.GO_HTTP_CLIENT)

        if not isinstance(request, GoHTTPRequest):
            msg = f"bad request type: {type(request).__name__}, expected GoHTTPRequest"
            raise TypeError(msg)

        headers = dict(request.headers)
        existing_headers_lower = {k.lower() for k in headers}
        is_ua_placeholder = payload_info.placeholder_name == "UserAgent"
        for header, value in self._headers.items():
            if header.lower() == UA_HEADER.lower() and is_ua_placeholder:
                continue
            if header.lower() not in existing_headers_lower:
                headers[header] = value

        if payload_info.debug_header_value:
            headers[GTW_DEBUG_HEADER] = payload_info.debug_header_value

        content: bytes | None = None
        if isinstance(request.content, str):
            content = request.content.encode("utf-8")
        elif isinstance(request.content, bytes):
            content = request.content

        client = await self._get_client()
        resp = await client.request(
            method=request.method,
            url=request.url,
            headers=headers,
            content=content,
        )

        resp_headers: dict[str, list[str]] = {}
        for key, value in resp.headers.multi_items():
            resp_headers.setdefault(key, []).append(value)

        return ResponseMeta(
            status_code=resp.status_code,
            status_reason=resp.reason_phrase or "",
            headers=resp_headers,
            content=resp.content,
        )


def _check_answer(body: bytes) -> bool:
    """Check that the response contains __typename indicating GraphQL.

    Args:
        body: Response body bytes.

    Returns:
        True if the response looks like a GraphQL response.
    """
    try:
        json_map = orjson.loads(body)
    except Exception:
        return False

    if not isinstance(json_map, dict):
        return False

    data = json_map.get("data")
    if not isinstance(data, dict):
        return False

    return "__typename" in data
