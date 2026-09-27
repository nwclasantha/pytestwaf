"""Data models for test cases and test results."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from gotestwaf.payload.placeholder.placeholder import PlaceholderConfig


@dataclass(slots=True)
class Info:
    """Information about a single test result."""

    payload: str = ""
    encoder: str = ""
    placeholder: str = ""
    set: str = ""
    case: str = ""
    response_status_code: int = 0
    response_time_ms: float = 0.0
    additional_info: list[str] = field(default_factory=list)
    type: str = ""
    # Full HTTP request/response for PoC evidence
    request_method: str = ""
    request_url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""


@dataclass(slots=True)
class Placeholder:
    """A placeholder with optional configuration."""

    name: str = ""
    config: PlaceholderConfig | None = None

    def hash(self) -> bytes:
        sha256sum = hashlib.sha256()
        sha256sum.update(self.name.encode())
        if self.config is not None:
            sha256sum.update(self.config.hash())
        return sha256sum.digest()


@dataclass(slots=True)
class Case:
    """A test case with payloads, encoders, and placeholders."""

    payloads: list[str] = field(default_factory=list)
    encoders: list[str] = field(default_factory=list)
    placeholders: list[Placeholder] = field(default_factory=list)
    type: str = "unknown"
    set: str = ""
    name: str = ""
    is_true_positive: bool = True

    def hash(self) -> bytes:
        sha256sum = hashlib.sha256()

        for p in self.payloads:
            sha256sum.update(p.encode())

        for e in self.encoders:
            sha256sum.update(e.encode())

        for ph in self.placeholders:
            sha256sum.update(ph.hash())

        sha256sum.update(self.type.encode())
        sha256sum.update(self.set.encode())
        sha256sum.update(self.name.encode())

        sha256sum.update(b"\x01" if self.is_true_positive else b"\x00")

        return sha256sum.digest()
