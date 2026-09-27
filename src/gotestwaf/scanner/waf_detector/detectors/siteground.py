"""SiteGround WAF/bot protection detector."""

from __future__ import annotations

from gotestwaf.scanner.waf_detector.detectors.checks import (
    and_checks,
    check_content,
    check_cookie,
    check_header,
    check_status_code,
    or_checks,
)
from gotestwaf.scanner.waf_detector.detectors.detectors import Detector


def siteground_waf() -> Detector:
    """Create SiteGround WAF detector.

    Separate detection (broad) from block checking (specific).
    SiteGround's sgcaptcha appears on challenge pages, not WAF blocks.
    """
    return Detector(
        waf_name="SiteGround Security",
        vendor="SiteGround",
        # Detection: "is SiteGround present?"
        is_waf_check=or_checks(
            check_header("sg-captcha", ".", attack=False),
            check_cookie("sg_cookies_test", attack=False),
            check_content("sgcaptcha", attack=False),
            check_content("sg-captcha-form", attack=False),
            check_content("siteground", attack=True),
        ),
        # Block check: "did SiteGround block THIS request?"
        # Only match actual security blocks, not CAPTCHA pages
        check=or_checks(
            and_checks(
                check_status_code(403, attack=True),
                check_content("siteground", attack=True),
            ),
            check_header("x-sucuri-id", ".", attack=True),
        ),
    )
