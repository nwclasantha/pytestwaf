"""WAF detection logic."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

import httpx

from gotestwaf.helpers.url import get_target_url_str
from gotestwaf.helpers.utils import deep_copy_map
from gotestwaf.scanner.types.response import GoHTTPResponse
from gotestwaf.scanner.waf_detector.detectors.checks import Check, Responses
from gotestwaf.scanner.waf_detector.detectors.detectors import get_detectors

if TYPE_CHECKING:
    from gotestwaf.config.config import Config

XSS_PAYLOAD = '<script>alert("XSS");</script>'
SQLI_PAYLOAD = "UNION SELECT ALL FROM information_schema AND ' or SLEEP(5) or '"
LFI_PAYLOAD = "../../../../etc/passwd"
RCE_PAYLOAD = "/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com"
XXE_PAYLOAD = '<!ENTITY xxe SYSTEM "file:///etc/shadow">]><pwn>&hack;</pwn>'


class WAFDetector:
    """Detects WAF solutions by analyzing HTTP responses."""

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._target = get_target_url_str(cfg.url)

        self._headers = deep_copy_map(cfg.http_headers)
        custom_header_parts = cfg.add_header.split(":", 1)
        if len(custom_header_parts) > 1:
            self._headers[custom_header_parts[0].strip()] = custom_header_parts[1].strip()

        self._host_header = self._headers.get("Host", "")
        self._verify_ssl = cfg.tls_verify

        # Load session cookies (set by CAPTCHA solver) so detection works
        # behind bot protection
        self._cookies: dict[str, str] = {}
        self._load_session_cookies()

    def _load_session_cookies(self) -> None:
        """Load session cookies from file if available (shared with gohttp client)."""
        from gotestwaf.scanner.clients.gohttp.client import _load_session_cookies
        self._cookies = _load_session_cookies()

    async def do_request(self) -> httpx.Response:
        """Send a normal HTTP request (no attack payload)."""
        async with httpx.AsyncClient(verify=self._verify_ssl, follow_redirects=True, timeout=30.0) as client:
            headers = dict(self._headers)
            if self._host_header:
                headers["Host"] = self._host_header
            resp = await client.get(self._target, headers=headers, cookies=self._cookies or None)
            return resp

    async def do_malicious_request(self) -> httpx.Response:
        """Send an HTTP request with attack payloads in query parameters."""
        params = {
            "a": XSS_PAYLOAD,
            "b": SQLI_PAYLOAD,
            "c": LFI_PAYLOAD,
            "d": RCE_PAYLOAD,
            "e": XXE_PAYLOAD,
        }
        url = f"{self._target}?{urlencode(params)}"

        async with httpx.AsyncClient(verify=self._verify_ssl, follow_redirects=True, timeout=30.0) as client:
            headers = dict(self._headers)
            if self._host_header:
                headers["Host"] = self._host_header
            resp = await client.get(url, headers=headers, cookies=self._cookies or None)
            return resp

    async def detect_waf(self) -> tuple[str, str, Check | None]:
        """Perform WAF identification.

        Returns:
            Tuple of (waf_name, vendor, check_function). Empty strings if no WAF detected.
        """
        resp = await self.do_request()
        resp_to_attack = await self.do_malicious_request()

        resps = Responses(
            resp=GoHTTPResponse(resp=resp),
            resp_to_attack=GoHTTPResponse(resp=resp_to_attack),
        )

        for detector in get_detectors():
            if detector.is_waf(resps):
                return detector.waf_name, detector.vendor, detector.check

        return "", "", None
