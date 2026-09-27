"""Response type definitions for GoTestWAF scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

import httpx


@runtime_checkable
class Response(Protocol):
    """Protocol for response types."""

    def get_status_code(self) -> int: ...
    def get_reason(self) -> str: ...
    def get_headers(self) -> dict[str, list[str]]: ...
    def get_content(self) -> bytes: ...
    def get_error(self) -> Exception | None: ...


@dataclass(slots=True)
class GoHTTPResponse:
    """Response wrapper for standard httpx responses."""

    resp: httpx.Response

    def get_status_code(self) -> int:
        return self.resp.status_code

    def get_reason(self) -> str:
        return self.resp.reason_phrase or ""

    def get_headers(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for key, value in self.resp.headers.multi_items():
            result.setdefault(key, []).append(value)
        return result

    def get_content(self) -> bytes:
        return self.resp.content

    def get_error(self) -> Exception | None:
        return None


@dataclass(slots=True)
class ResponseMeta:
    """Response metadata for Chrome HTTP client or gRPC responses."""

    status_code: int = 0
    status_reason: str = ""
    headers: dict[str, list[str]] = field(default_factory=dict)
    content: bytes = b""
    error: str = ""

    def get_status_code(self) -> int:
        return self.status_code

    def get_reason(self) -> str:
        return self.status_reason

    def get_headers(self) -> dict[str, list[str]]:
        return self.headers

    def get_content(self) -> bytes:
        return self.content

    def get_error(self) -> Exception | None:
        if self.error:
            return RuntimeError(self.error)
        return None
