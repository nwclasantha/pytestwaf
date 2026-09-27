"""URLPath placeholder - places payload in URL path."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

from gotestwaf.payload.placeholder.placeholder import PlaceholderConfig
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest, Request


@dataclass(slots=True)
class URLPathPlaceholder:
    """Places payload in the URL path."""

    name: str = "URLPath"

    def new_placeholder_config(self, conf: dict[Any, Any]) -> PlaceholderConfig | None:
        return None

    def get_name(self) -> str:
        return self.name

    def create_request(
        self,
        request_url: str,
        payload: str,
        config: PlaceholderConfig | None,
        http_client_type: HTTPClientType,
    ) -> Request:
        # Append payload to the path component only — preserves any
        # query string and fragment on the target URL. Naive string
        # concatenation would push the payload into the query string
        # for URLs like "https://target.com/api?token=secret".
        parsed = urlparse(request_url)
        new_path = (parsed.path or "/").rstrip("/") + "/" + payload
        url_with_payload = urlunparse((
            parsed.scheme, parsed.netloc, new_path,
            parsed.params, parsed.query, parsed.fragment,
        ))

        return GoHTTPRequest(
            method="GET",
            url=url_with_payload,
        )


default_url_path = URLPathPlaceholder()
