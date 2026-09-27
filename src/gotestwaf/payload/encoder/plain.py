"""Plain text encoder (no-op) implementation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class PlainEncoder:
    """Plain text encoder that returns data as-is."""

    name: str = "Plain"

    def get_name(self) -> str:
        return self.name

    def encode(self, data: str) -> str:
        return data


default_plain_encoder = PlainEncoder()
