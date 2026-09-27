"""Google Cloud Platform WAF detectors."""

from __future__ import annotations

from gotestwaf.scanner.waf_detector.detectors.checks import (
    check_content,
    check_header,
    or_checks,
)
from gotestwaf.scanner.waf_detector.detectors.detectors import Detector


def gcp_cloud_armor() -> Detector:
    return Detector(
        waf_name="Cloud Armor",
        vendor="Google Cloud",
        check=or_checks(
            check_header("server", "Google Frontend", attack=False),
            check_header("x-goog-iap-generated-response", ".", attack=False),
            check_content("google cloud armor", attack=True),
            check_content("your client has issued a malicious request", attack=True),
            check_content("error 403.*google", attack=True),
        ),
    )


def gcp_cloud_cdn() -> Detector:
    return Detector(
        waf_name="Cloud CDN",
        vendor="Google Cloud",
        check=or_checks(
            check_header("via", "google", attack=False),
            check_header("x-goog-hash", ".", attack=False),
            check_header("server", "gws", attack=False),
        ),
    )
