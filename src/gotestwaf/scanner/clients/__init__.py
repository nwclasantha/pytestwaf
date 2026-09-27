"""Scanner HTTP/gRPC/GraphQL client implementations."""

from __future__ import annotations

from typing import Protocol

from gotestwaf.payload.payload import PayloadInfo
from gotestwaf.scanner.types.request import Request
from gotestwaf.scanner.types.response import Response

GTW_DEBUG_HEADER = "X-GoTestWAF-Test"


class HTTPClient(Protocol):
    """Protocol for HTTP clients."""

    async def send_payload(self, target_url: str, payload_info: PayloadInfo) -> Response: ...
    async def send_request(self, req: Request) -> Response: ...


class GraphQLClient(Protocol):
    """Protocol for GraphQL clients."""

    async def check_availability(self) -> bool: ...
    def is_available(self) -> bool: ...
    async def send_payload(self, payload_info: PayloadInfo) -> Response: ...


class GRPCClient(Protocol):
    """Protocol for gRPC clients."""

    async def check_availability(self) -> bool: ...
    def is_available(self) -> bool: ...
    async def send_payload(self, payload_info: PayloadInfo) -> Response: ...
    async def close(self) -> None: ...
