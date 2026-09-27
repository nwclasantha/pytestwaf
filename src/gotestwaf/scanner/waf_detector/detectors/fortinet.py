"""Fortinet FortiWeb / FortiGate WAF detectors."""

from __future__ import annotations

from gotestwaf.scanner.waf_detector.detectors.checks import (
    check_content,
    check_cookie,
    check_header,
    or_checks,
)
from gotestwaf.scanner.waf_detector.detectors.detectors import Detector


def fortiweb() -> Detector:
    return Detector(
        waf_name="FortiWeb",
        vendor="Fortinet",
        check=or_checks(
            check_header("server", "FortiWeb", attack=False),
            check_cookie("FORTIWAFSID", attack=False),
            check_content("fortigate", attack=True),
            check_content("fortiweb", attack=True),
            check_content(".fgd_icon", attack=True),
            check_content("web page blocked", attack=True),
        ),
    )


def fortigate() -> Detector:
    return Detector(
        waf_name="FortiGate",
        vendor="Fortinet",
        check=or_checks(
            check_header("server", "FortiGate", attack=False),
            check_cookie("APSCOOKIE_", attack=False),
            check_content("fortigate", attack=True),
            check_content("blocked by fortiguard", attack=True),
        ),
    )
