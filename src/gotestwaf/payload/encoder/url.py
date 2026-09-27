"""URL encoder implementation."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote


@dataclass(slots=True)
class URLEncoder:
    """URL path escape encoder."""

    name: str = "URL"

    def get_name(self) -> str:
        return self.name

    def encode(self, data: str) -> str:
        # Go's url.PathEscape leaves sub-delimiters unescaped:
        # unreserved: A-Za-z0-9 - . _ ~ (quote's default for safe="")
        # sub-delims that PathEscape also leaves unescaped: ! $ & ' ( ) * + , ; = : @
        return quote(data, safe="!$&'()*+,;=:@")


default_url_encoder = URLEncoder()
