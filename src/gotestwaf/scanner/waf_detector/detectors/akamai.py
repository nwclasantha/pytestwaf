"""Akamai WAF detector."""

from __future__ import annotations

from gotestwaf.scanner.waf_detector.detectors.checks import check_header, or_checks
from gotestwaf.scanner.waf_detector.detectors.detectors import Detector


def kona_site_defender() -> Detector:
    """Create Akamai Kona SiteDefender detector."""
    return Detector(
        waf_name="Kona SiteDefender",
        vendor="Akamai",
        check=or_checks(
            check_header("Server", "AkamaiGHost", attack=False),
            check_header("Server", "AkamaiGHost", attack=True),
        ),
    )
