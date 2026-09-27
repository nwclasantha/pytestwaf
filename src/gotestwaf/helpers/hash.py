"""Hash interface protocol."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class HashProtocol(Protocol):
    """Protocol for objects that can produce a hash digest."""

    def hash(self) -> bytes: ...
