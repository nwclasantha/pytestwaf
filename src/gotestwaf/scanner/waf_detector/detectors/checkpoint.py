"""Check Point WAF detectors."""

from __future__ import annotations

from gotestwaf.scanner.waf_detector.detectors.checks import (
    check_content,
    check_cookie,
    check_header,
    or_checks,
)
from gotestwaf.scanner.waf_detector.detectors.detectors import Detector


def checkpoint_waf() -> Detector:
    return Detector(
        waf_name="CloudGuard AppSec",
        vendor="Check Point",
        check=or_checks(
            check_header("server", "Check Point", attack=False),
            check_header("x-checkpoint", ".", attack=True),
            check_cookie("cpwebsession", attack=False),
            check_content("check point", attack=True),
            check_content("cloudguard", attack=True),
            check_content("user.*space.*firewall", attack=True),
        ),
    )
