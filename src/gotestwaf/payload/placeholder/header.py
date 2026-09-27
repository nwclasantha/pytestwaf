"""Header placeholder - places payload in a custom HTTP header."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gotestwaf.payload.placeholder.placeholder import PlaceholderConfig
from gotestwaf.payload.placeholder.utils import random_hex
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest, Request

SEED = 5


@dataclass(slots=True)
class HeaderPlaceholder:
    """Places payload in a random custom HTTP header."""

    name: str = "Header"

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
        random_header = f"X-{random_name}"

        return GoHTTPRequest(
            method="GET",
            url=request_url,
            headers={random_header: payload},
        )


default_header = HeaderPlaceholder()
