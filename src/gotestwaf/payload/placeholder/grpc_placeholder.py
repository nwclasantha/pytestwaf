"""gRPC placeholder - stub for gRPC payload placement."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gotestwaf.payload.placeholder.placeholder import PlaceholderConfig
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import Request


@dataclass(slots=True)
class GRPCPlaceholder:
    """Placeholder for gRPC requests. CreateRequest raises NotImplementedError
    because gRPC requests are handled directly by the gRPC client."""

    name: str = "gRPC"

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
        msg = "gRPC placeholder does not create HTTP requests directly"
        raise RuntimeError(msg)


default_grpc = GRPCPlaceholder()
