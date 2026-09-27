"""Check functions for WAF detection."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gotestwaf.scanner.types.response import Response


@dataclass
class Responses:
    """Pair of responses for WAF detection: normal and attack."""

    resp: Any = None
    resp_to_attack: Any = None


# Type alias for check functions - uses Any at runtime to avoid circular imports
Check = Callable[[Responses], bool]


def check_status_code(status: int, attack: bool = True) -> Check:
    """Check if response status code matches."""
    def _check(resps: Responses) -> bool:
        resp = resps.resp_to_attack if attack else resps.resp
        if resp is None:
            return False
        return resp.get_status_code() == status
    return _check


def check_reason(regex: str, attack: bool = True) -> Check:
    """Check if response reason matches regex."""
    pattern = re.compile(regex)
    def _check(resps: Responses) -> bool:
        resp = resps.resp_to_attack if attack else resps.resp
        if resp is None:
            return False
        return bool(pattern.search(resp.get_reason()))
    return _check


def check_header(header: str, regex: str, attack: bool = False) -> Check:
    """Check if response header value matches regex.

    If `header` contains regex metacharacters (e.g. '.*'), it is treated as
    a pattern to match against all header names. Otherwise it is used as a
    direct dict lookup key.
    """
    value_pattern = re.compile(regex)
    header_lower = header.lower()
    # Detect if header name itself is a regex pattern
    _is_header_regex = any(c in header for c in r".*+?[](){}|^$\\")
    _header_name_pattern = re.compile(header_lower) if _is_header_regex else None
    def _check(resps: Responses) -> bool:
        resp = resps.resp_to_attack if attack else resps.resp
        if resp is None:
            return False
        headers = resp.get_headers()
        if _header_name_pattern is not None:
            # Regex header name: match against all header keys
            for hdr_name, values in headers.items():
                if _header_name_pattern.search(hdr_name.lower()):
                    if any(value_pattern.search(v) for v in values):
                        return True
            return False
        # Direct lookup (fast path)
        values = headers.get(header_lower, headers.get(header, []))
        return any(value_pattern.search(v) for v in values)
    return _check


def check_cookie(regex: str, attack: bool = False) -> Check:
    """Check if Set-Cookie header matches regex."""
    return check_header("Set-Cookie", regex, attack)


def check_content(regex: str, attack: bool = True) -> Check:
    """Check if response body matches regex."""
    pattern = re.compile(regex.encode() if isinstance(regex, str) else regex, re.IGNORECASE)
    def _check(resps: Responses) -> bool:
        resp = resps.resp_to_attack if attack else resps.resp
        if resp is None:
            return False
        body = resp.get_content()
        if not body:
            return False
        return bool(pattern.search(body))
    return _check


def and_checks(*checks: Check) -> Check:
    """Combine checks with AND logic."""
    def _check(resps: Responses) -> bool:
        return all(check(resps) for check in checks)
    return _check


def or_checks(*checks: Check) -> Check:
    """Combine checks with OR logic."""
    def _check(resps: Responses) -> bool:
        return any(check(resps) for check in checks)
    return _check
