"""Request type definitions for GoTestWAF scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import httpx

from gotestwaf.scanner.types.response import ResponseMeta


@runtime_checkable
class Request(Protocol):
    """Protocol for request types."""

    def is_request(self) -> None: ...


@dataclass(slots=True)
class GoHTTPRequest:
    """Request wrapper for standard HTTP requests using httpx."""

    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes | str | None = None
    debug_header_value: str = ""

    def is_request(self) -> None:
        """Tag method for Request protocol."""

    def to_httpx_request(self) -> httpx.Request:
        """Convert to an httpx.Request object."""
        body: bytes | None = None
        if isinstance(self.content, str):
            body = self.content.encode("utf-8")
        elif isinstance(self.content, bytes):
            body = self.content
        return httpx.Request(
            method=self.method,
            url=self.url,
            headers=self.headers,
            content=body,
        )


@dataclass(slots=True)
class ChromeDPTasks:
    """Request wrapper for Chrome DevTools Protocol tasks."""

    tasks: list[Any] = field(default_factory=list)
    user_agent_header: dict[str, str] = field(default_factory=dict)
    response_meta: ResponseMeta | None = None
    debug_header_value: str = ""

    def is_request(self) -> None:
        """Tag method for Request protocol."""
