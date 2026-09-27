"""Barracuda WAF detector."""

from __future__ import annotations

from gotestwaf.scanner.waf_detector.detectors.checks import (
    check_content,
    check_cookie,
    check_header,
    or_checks,
)
from gotestwaf.scanner.waf_detector.detectors.detectors import Detector


def barracuda_waf() -> Detector:
    return Detector(
        waf_name="Barracuda WAF",
        vendor="Barracuda Networks",
        check=or_checks(
            check_header("server", "Barracuda", attack=False),
            check_cookie("barra_counter_session", attack=False),
            check_cookie("BNI__BARRAESSION", attack=False),
            check_content("barracuda", attack=True),
            # Dropped: "you have been blocked" — generic phrasing used by
            # Cloudflare, nginx 403 templates, and many other WAFs.
            check_content("barracuda networks", attack=True),
        ),
    )
