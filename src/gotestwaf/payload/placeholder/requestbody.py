"""RequestBody placeholder - places payload as generic request body."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gotestwaf.payload.placeholder.placeholder import PlaceholderConfig
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest, Request


@dataclass(slots=True)
class RequestBodyPlaceholder:
    """Places payload as the raw request body in a POST request."""

    name: str = "RequestBody"

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
        return GoHTTPRequest(
            method="POST",
            url=request_url,
            content=payload,
        )


default_request_body = RequestBodyPlaceholder()
