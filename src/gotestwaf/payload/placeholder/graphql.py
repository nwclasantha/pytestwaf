"""GraphQL placeholder - places payload in GraphQL requests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

from gotestwaf.errors import BadPlaceholderConfigError
from gotestwaf.payload.placeholder.placeholder import PlaceholderConfig
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest, Request


@dataclass(slots=True)
class GraphQLConfig:
    """Configuration for GraphQL placeholder."""

    method: str = "GET"

    def hash(self) -> bytes:
        sha256sum = hashlib.sha256()
        sha256sum.update(self.method.encode())
        return sha256sum.digest()


@dataclass(slots=True)
class GraphQLPlaceholder:
    """Places payload in GraphQL GET or POST requests."""

    name: str = "GraphQL"

    def new_placeholder_config(self, conf: dict[Any, Any]) -> PlaceholderConfig | None:
        method = conf.get("method")
        if method is None:
            raise BadPlaceholderConfigError(self.name, "empty method")
        if not isinstance(method, str):
            raise BadPlaceholderConfigError(
                self.name, f"unknown type of 'method' field, expected string, got {type(method).__name__}"
            )
        if method not in ("GET", "POST"):
            raise BadPlaceholderConfigError(
                self.name, f"unknown HTTP method, expected GET or POST, got {method}"
            )
        return GraphQLConfig(method=method)

    def get_name(self) -> str:
        return self.name

    def create_request(
        self,
        request_url: str,
        payload: str,
        config: PlaceholderConfig | None,
        http_client_type: HTTPClientType,
    ) -> Request:
        if not isinstance(config, GraphQLConfig):
            raise BadPlaceholderConfigError(
                self.name,
                f"bad config type: got {type(config).__name__}, expected: GraphQLConfig",
            )

        parsed = urlparse(request_url)

        match config.method:
            case "GET":
                # Preserve existing query params and add/replace "query" param
                # (mirrors Go's reqURL.Query() which retains existing params)
                from urllib.parse import parse_qs, urlencode as _urlencode
                existing_params = parse_qs(parsed.query, keep_blank_values=True)
                # Flatten single-value lists for urlencode
                flat_params = {k: v[0] if len(v) == 1 else v for k, v in existing_params.items()}
                flat_params["query"] = payload
                query = _urlencode(flat_params, doseq=True)
                url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))
                return GoHTTPRequest(method="GET", url=url)
            case "POST":
                return GoHTTPRequest(method="POST", url=request_url, content=payload)
            case _:
                raise BadPlaceholderConfigError(
                    self.name, f"unknown HTTP method: {config.method}"
                )


default_graphql = GraphQLPlaceholder()
