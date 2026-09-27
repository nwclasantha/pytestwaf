"""Typed exception hierarchy for GoTestWAF."""

from __future__ import annotations


class GoTestWAFError(Exception):
    """Base exception for all GoTestWAF errors."""


class ConfigError(GoTestWAFError):
    """Configuration-related errors."""


class ScanError(GoTestWAFError):
    """Scanning-related errors."""


class PayloadError(GoTestWAFError):
    """Payload encoding or placeholder errors."""


class UnknownEncoderError(PayloadError):
    """Raised when an unknown encoder name is used."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"unknown encoder: {name}")


class UnknownPlaceholderError(PayloadError):
    """Raised when an unknown placeholder name is used."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"unknown placeholder: {name}")


class BadPlaceholderConfigError(PayloadError):
    """Raised when a placeholder has invalid configuration."""

    def __init__(self, name: str, reason: str | None = None) -> None:
        self.name = name
        if reason:
            msg = f"bad config for {name} placeholder: {reason}"
        else:
            msg = f"bad config for {name} placeholder"
        super().__init__(msg)


class ReportError(GoTestWAFError):
    """Report generation errors."""


class WAFDetectionError(GoTestWAFError):
    """WAF detection errors."""


class ClientError(GoTestWAFError):
    """HTTP/gRPC/GraphQL client errors."""


class UnknownHTTPClientError(ClientError):
    """Raised when an unknown HTTP client type is specified."""

    def __init__(self, client_type: str) -> None:
        self.client_type = client_type
        super().__init__(
            f"unknown HTTP client type: {client_type}, expected GoHTTPClient or ChromeHTTPClient"
        )


class ValidationError(GoTestWAFError):
    """Data validation error."""
