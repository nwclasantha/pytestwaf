"""Imperva WAF detectors."""

from __future__ import annotations

from gotestwaf.scanner.waf_detector.detectors.checks import (
    and_checks,
    check_content,
    check_cookie,
    or_checks,
)
from gotestwaf.scanner.waf_detector.detectors.detectors import Detector


def incapsula() -> Detector:
    """Create Imperva Incapsula detector."""
    return Detector(
        waf_name="Incapsula",
        vendor="Imperva Inc.",
        check=or_checks(
            check_cookie(r"^incap_ses.*?=", attack=False),
            check_cookie(r"^visid_incap.*?=", attack=False),
            check_content("incapsula incident id", attack=True),
            check_content("powered by incapsula", attack=True),
            check_content("/_Incapsula_Resource", attack=True),
        ),
    )


def secure_sphere() -> Detector:
    """Create Imperva SecureSphere detector."""
    return Detector(
        waf_name="SecureSphere",
        vendor="Imperva Inc.",
        check=and_checks(
            check_content("<(title|h2)>Error", attack=True),
            check_content("The incident ID is", attack=True),
            check_content("This page can't be displayed", attack=True),
            check_content("Contact support for additional information", attack=True),
        ),
    )
