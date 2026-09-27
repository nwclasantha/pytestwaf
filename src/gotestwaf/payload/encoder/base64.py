"""Base64 encoder implementations."""

from __future__ import annotations

import base64
import enum
from dataclasses import dataclass


class Base64Mode(enum.IntEnum):
    """Base64 encoding modes."""

    NORMAL = 0
    FLAT = 1


@dataclass(slots=True)
class Base64Encoder:
    """Base64 encoder with normal and flat (no padding) modes."""

    name: str
    mode: Base64Mode

    def get_name(self) -> str:
        return self.name

    def encode(self, data: str) -> str:
        encoded = base64.b64encode(data.encode("utf-8")).decode("ascii")
        if self.mode == Base64Mode.FLAT:
            encoded = encoded.rstrip("=")
        return encoded


default_base64_encoder = Base64Encoder(name="Base64", mode=Base64Mode.NORMAL)
default_base64_flat_encoder = Base64Encoder(name="Base64Flat", mode=Base64Mode.FLAT)
