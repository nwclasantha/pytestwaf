"""URL utility functions."""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse


def get_target_url(req_url: str) -> str:
    """Return URL with empty path, query, and fragment parts.

    Args:
        req_url: The full request URL.

    Returns:
        URL string with only scheme, netloc, and no path/query/fragment.
    """
    parsed = urlparse(req_url)
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def get_target_url_str(req_url: str) -> str:
    """Return URL string with empty path, query, and fragment parts.

    Args:
        req_url: The full request URL.

    Returns:
        Clean URL string.
    """
    return get_target_url(req_url)


def host_port_from_url(waf_url: str, port: int) -> tuple[bool, str]:
    """Extract host:port from a URL, replacing the port.

    Args:
        waf_url: The WAF URL to parse.
        port: The port number to use.

    Returns:
        Tuple of (is_tls, host_port_string).

    Raises:
        ValueError: If URL cannot be parsed.
    """
    parsed = urlparse(waf_url)
    if not parsed.hostname:
        # Sanitize URL to avoid leaking credentials in error messages
        safe_url = urlunparse((parsed.scheme, parsed.netloc, "", "", "", "")) if parsed.netloc else waf_url
        msg = f"couldn't parse host from URL: {safe_url}"
        raise ValueError(msg)

    host = parsed.hostname
    is_tls = parsed.scheme == "https"
    host_port = f"{host}:{port}"

    return is_tls, host_port
