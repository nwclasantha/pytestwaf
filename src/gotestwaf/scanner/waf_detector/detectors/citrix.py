"""Citrix NetScaler / ADC WAF detector."""

from __future__ import annotations

from gotestwaf.scanner.waf_detector.detectors.checks import (
    check_content,
    check_cookie,
    check_header,
    or_checks,
)
from gotestwaf.scanner.waf_detector.detectors.detectors import Detector


def netscaler_appfw() -> Detector:
    return Detector(
        waf_name="NetScaler AppFirewall",
        vendor="Citrix",
        check=or_checks(
            check_header("via", "NS-CACHE", attack=False),
            check_header("x-nsprotect", ".", attack=True),
            check_cookie("ns_af", attack=False),
            check_cookie("citrix_ns_id", attack=False),
            check_cookie("NSC_", attack=False),
            check_content("ns_af", attack=True),
            check_content("citrix.*application firewall", attack=True),
            check_content("appfw.*session", attack=True),
            check_content("violation.*netscaler", attack=True),
        ),
    )
