"""UserAgent placeholder - places payload in User-Agent header."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gotestwaf.payload.placeholder.placeholder import PlaceholderConfig
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest, Request

UA_HEADER = "User-Agent"


@dataclass(slots=True)
class UserAgentPlaceholder:
    """Places payload in the User-Agent HTTP header."""

    name: str = "UserAgent"

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
            method="GET",
            url=request_url,
            headers={UA_HEADER: payload},
        )


default_user_agent = UserAgentPlaceholder()
