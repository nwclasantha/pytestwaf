"""User-Agent rotation for evading bot detection fingerprinting.

Provides realistic browser UA strings with matching Sec-Ch-Ua headers.
Rotates UA per batch of requests (same UA for 30 requests, then switch).
"""

from __future__ import annotations

import random
from dataclasses import dataclass

UA_POOL = [
    {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="131", "Not_A Brand";v="24"',
        "sec_ch_ua_platform": '"Windows"',
    },
    {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="130", "Not_A Brand";v="24"',
        "sec_ch_ua_platform": '"Windows"',
    },
    {
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="131", "Not_A Brand";v="24"',
        "sec_ch_ua_platform": '"macOS"',
    },
    {
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="131", "Not_A Brand";v="24"',
        "sec_ch_ua_platform": '"Linux"',
    },
    {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
        "sec_ch_ua": "",
        "sec_ch_ua_platform": "",
    },
    {
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
        "sec_ch_ua": "",
        "sec_ch_ua_platform": "",
    },
    {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        "sec_ch_ua": '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_ch_ua_platform": '"Windows"',
    },
    {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="129", "Not_A Brand";v="24"',
        "sec_ch_ua_platform": '"Windows"',
    },
]


class UARotator:
    """Rotates User-Agent strings across request batches."""

    def __init__(self, batch_size: int = 30) -> None:
        self._pool = list(UA_POOL)
        self._batch_size = batch_size
        self._current_idx = random.randint(0, len(self._pool) - 1)
        self._request_count = 0

    def advance(self) -> None:
        """Advance the request counter. Call once per request."""
        self._request_count += 1
        if self._request_count >= self._batch_size:
            self._request_count = 0
            self._current_idx = (self._current_idx + 1) % len(self._pool)

    def get_ua(self) -> dict[str, str]:
        """Get current UA entry WITHOUT advancing counter."""
        return self._pool[self._current_idx]

    def get_headers(self) -> dict[str, str]:
        """Get full header set for current UA (does NOT advance counter)."""
        ua = self.get_ua()
        headers: dict[str, str] = {
            "User-Agent": ua["user_agent"],
        }
        if ua.get("sec_ch_ua"):
            headers["Sec-Ch-Ua"] = ua["sec_ch_ua"]
            headers["Sec-Ch-Ua-Mobile"] = "?0"
        if ua.get("sec_ch_ua_platform"):
            headers["Sec-Ch-Ua-Platform"] = ua["sec_ch_ua_platform"]
        return headers

    def get_current_user_agent(self) -> str:
        """Get just the User-Agent string."""
        return self._pool[self._current_idx]["user_agent"]
