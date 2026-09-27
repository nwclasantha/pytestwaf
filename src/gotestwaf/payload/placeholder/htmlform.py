"""HTMLForm placeholder - places payload as URL-encoded form data."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote_plus

from gotestwaf.payload.placeholder.placeholder import PlaceholderConfig
from gotestwaf.payload.placeholder.utils import random_hex
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest, Request

# Detects payloads that already look percent-encoded (e.g. produced by URL encoder).
# Conservative — looks for at least one valid %XX hex sequence and no raw form-breaking chars.
_PERCENT_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")

SEED = 5


@dataclass(slots=True)
class HTMLFormPlaceholder:
    """Places payload as URL-encoded form data in a POST request."""

    name: str = "HTMLForm"

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
        random_name = random_hex(SEED)
        # Form values must be percent-encoded so the body parses correctly.
        # If the payload is already URL-encoded (URL encoder), use it verbatim
        # to avoid double-encoding (% -> %25). Otherwise, encode now.
        already_encoded = bool(_PERCENT_ENCODED_RE.search(payload)) and "&" not in payload and "=" not in payload
        encoded_value = payload if already_encoded else quote_plus(payload)
        body_payload = f"{random_name}={encoded_value}"

        return GoHTTPRequest(
            method="POST",
            url=request_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            content=body_payload,
        )


default_html_form = HTMLFormPlaceholder()
