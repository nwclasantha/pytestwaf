"""RawRequest placeholder - constructs arbitrary HTTP requests from config."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlparse, urlunparse

from gotestwaf.errors import BadPlaceholderConfigError
from gotestwaf.payload.placeholder.placeholder import PAYLOAD_PLACEHOLDER, PlaceholderConfig
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest, Request


@dataclass(slots=True)
class RawRequestConfig:
    """Configuration for raw request placeholder."""

    method: str = ""
    path: str = "/"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    def hash(self) -> bytes:
        sha256sum = hashlib.sha256()
        sha256sum.update(self.method.encode())
        sha256sum.update(self.path.encode())
        for header, value in self.headers.items():
            sha256sum.update(header.encode())
            sha256sum.update(value.encode())
        sha256sum.update(self.body.encode())
        return sha256sum.digest()


@dataclass(slots=True)
class RawRequestPlaceholder:
    """Creates arbitrary HTTP requests from a full config specification."""

    name: str = "RawRequest"

    def new_placeholder_config(self, conf: dict[Any, Any]) -> PlaceholderConfig | None:
        result = RawRequestConfig()

        method = conf.get("method")
        if method is None:
            raise BadPlaceholderConfigError(self.name, "empty method")
        if not isinstance(method, str):
            raise BadPlaceholderConfigError(
                self.name,
                f"unknown type of 'method' field, expected string, got {type(method).__name__}",
            )
        result.method = method

        path = conf.get("path")
        if path is None:
            result.path = "/"
        elif not isinstance(path, str):
            raise BadPlaceholderConfigError(
                self.name,
                f"unknown type of 'path' field, expected string, got {type(path).__name__}",
            )
        else:
            result.path = path if path else "/"

        headers = conf.get("headers")
        if headers is not None:
            if not isinstance(headers, dict):
                raise BadPlaceholderConfigError(
                    self.name,
                    f"unknown type of 'headers' field, expected dict, got {type(headers).__name__}",
                )
            for k, v in headers.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    raise BadPlaceholderConfigError(
                        self.name,
                        f"headers must be dict[str, str], got key={type(k).__name__}, value={type(v).__name__}",
                    )
                result.headers[k] = v

        body = conf.get("body")
        if body is not None:
            if not isinstance(body, str):
                raise BadPlaceholderConfigError(
                    self.name,
                    f"unknown type of 'body' field, expected string, got {type(body).__name__}",
                )
            result.body = body

        return result

    def get_name(self) -> str:
        return self.name

    def create_request(
        self,
        request_url: str,
        payload: str,
        config: PlaceholderConfig | None,
        http_client_type: HTTPClientType,
    ) -> Request:
        if not isinstance(config, RawRequestConfig):
            raise BadPlaceholderConfigError(
                self.name,
                f"bad config type: got {type(config).__name__}, expected: RawRequestConfig",
            )

        # Build URL — combine the configured path with the base path
        # component only, preserving any existing query string and fragment
        # on the target URL (naive string concatenation would push the
        # appended path into the query string for URLs like
        # "https://target.com/api?token=x").
        parsed = urlparse(request_url)
        base_path = parsed.path or "/"
        if not base_path.endswith("/"):
            base_path += "/"
        cfg_path = config.path[1:] if config.path.startswith("/") else config.path
        new_path = base_path + cfg_path
        request_url = urlunparse((
            parsed.scheme, parsed.netloc, new_path,
            parsed.params, parsed.query, parsed.fragment,
        ))

        # Replace payload placeholder in URL with URL-escaped payload
        # Go's url.PathEscape does NOT escape sub-delims or /
        request_url = request_url.replace(PAYLOAD_PLACEHOLDER, quote(payload, safe="!$&'()*+,;=:@/"))

        # Build body with payload substitution
        body = config.body.replace(PAYLOAD_PLACEHOLDER, payload) if config.body else ""

        # Build headers with payload substitution
        headers: dict[str, str] = {}
        for k, v in config.headers.items():
            headers[k] = v.replace(PAYLOAD_PLACEHOLDER, payload)

        content: bytes | str | None = body if body else None

        return GoHTTPRequest(
            method=config.method,
            url=request_url,
            headers=headers,
            content=content,
        )


default_raw_request = RawRequestPlaceholder()
