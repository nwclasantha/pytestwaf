"""XMLBody placeholder - places payload as XML body."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gotestwaf.payload.placeholder.placeholder import PlaceholderConfig
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest, Request


@dataclass(slots=True)
class XMLBodyPlaceholder:
    """Places payload as an XML body in a POST request."""

    name: str = "XMLBody"

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
            headers={"Content-Type": "application/xml"},
            content=payload,
        )


default_xml_body = XMLBodyPlaceholder()
