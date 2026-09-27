"""JSONRequest placeholder - places payload in a JSON object wrapper."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from gotestwaf.payload.placeholder.placeholder import PlaceholderConfig
from gotestwaf.payload.placeholder.utils import random_hex
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest, Request

SEED = 5


@dataclass(slots=True)
class JSONRequestPlaceholder:
    """Places payload in a JSON request with wrapper object."""

    name: str = "JSONRequest"

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
        param = random_hex(SEED)
        json_payload = json.dumps({"test": True, param: payload})

        return GoHTTPRequest(
            method="POST",
            url=request_url,
            headers={"Content-Type": "application/json"},
            content=json_payload,
        )


default_json_request = JSONRequestPlaceholder()
