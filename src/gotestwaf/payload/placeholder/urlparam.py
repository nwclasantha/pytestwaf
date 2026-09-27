"""URLParam placeholder - places payload in URL query parameters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

from gotestwaf.payload.placeholder.placeholder import PlaceholderConfig
from gotestwaf.payload.placeholder.utils import random_hex
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest, Request

SEED = 5


@dataclass(slots=True)
class URLParamPlaceholder:
    """Places payload as a URL query parameter."""

    name: str = "URLParam"

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
        parsed = urlparse(request_url)

        # Strip fragment (mirrors Go: reqURL.Fragment = "")
        url_no_fragment = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, parsed.query, "",
        ))

        param = random_hex(SEED)

        if parsed.query:
            # Existing query — append with &
            url_with_payload = f"{url_no_fragment}&{param}={payload}"
        else:
            # No query — strip trailing slashes, then add /? or ?
            # Mirrors Go's logic: find last non-slash char and decide
            stripped = url_no_fragment.rstrip("/")
            if not stripped:
                stripped = url_no_fragment

            # Check if the URL path ends with a non-slash character
            if parsed.path and not parsed.path.endswith("/"):
                url_with_payload = f"{stripped}?{param}={payload}"
            else:
                url_with_payload = f"{stripped}/?{param}={payload}"

        return GoHTTPRequest(
            method="GET",
            url=url_with_payload,
        )


default_url_param = URLParamPlaceholder()
