"""HTTP client type enumeration."""

from __future__ import annotations

import enum

from gotestwaf.errors import UnknownHTTPClientError


class HTTPClientType(enum.IntEnum):
    """Represents the type of HTTP client."""

    GO_HTTP_CLIENT = 0
    CHROME_HTTP_CLIENT = 1

    def __str__(self) -> str:
        match self:
            case HTTPClientType.GO_HTTP_CLIENT:
                return "GoHTTPClient"
            case HTTPClientType.CHROME_HTTP_CLIENT:
                return "ChromeHTTPClient"

    @classmethod
    def validate(cls, value: int) -> HTTPClientType:
        """Validate and return an HTTPClientType.

        Raises:
            UnknownHTTPClientError: If the value is not a valid client type.
        """
        try:
            return cls(value)
        except ValueError:
            raise UnknownHTTPClientError(str(value)) from None
