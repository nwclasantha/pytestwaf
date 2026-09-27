"""JavaScript Unicode encoder implementation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class JSUnicodeEncoder:
    """Encodes data as JavaScript Unicode escape sequences (UTF-16BE)."""

    name: str = "JSUnicode"

    def get_name(self) -> str:
        return self.name

    def encode(self, data: str) -> str:
        utf16be = data.encode("utf-16-be")
        result_parts: list[str] = []
        for i in range(0, len(utf16be), 2):
            result_parts.append(f"\\u{utf16be[i]:02x}{utf16be[i + 1]:02x}")
        return "".join(result_parts)


default_jsunicode_encoder = JSUnicodeEncoder()
