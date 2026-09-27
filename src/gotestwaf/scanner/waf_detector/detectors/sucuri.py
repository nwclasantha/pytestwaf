"""Sucuri WAF detector."""

from __future__ import annotations

from gotestwaf.scanner.waf_detector.detectors.checks import (
    check_content,
    check_cookie,
    check_header,
    or_checks,
)
from gotestwaf.scanner.waf_detector.detectors.detectors import Detector


def sucuri_waf() -> Detector:
    return Detector(
        waf_name="Sucuri WAF",
        vendor="Sucuri Inc. (GoDaddy)",
        check=or_checks(
            check_header("server", "Sucuri", attack=False),
            check_header("x-sucuri-id", ".", attack=False),
            check_header("x-sucuri-cache", ".", attack=False),
            check_content("sucuri website firewall", attack=True),
            check_content("sucuri cloudproxy", attack=True),
            check_content("access denied.*sucuri", attack=True),
            check_content("sucuri inc", attack=True),
        ),
    )
