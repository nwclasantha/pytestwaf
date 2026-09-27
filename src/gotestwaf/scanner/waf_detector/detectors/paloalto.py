"""Palo Alto Networks WAF detectors."""

from __future__ import annotations

from gotestwaf.scanner.waf_detector.detectors.checks import (
    check_content,
    check_header,
    or_checks,
)
from gotestwaf.scanner.waf_detector.detectors.detectors import Detector


def paloalto_prisma() -> Detector:
    return Detector(
        waf_name="Prisma Cloud WAAS",
        vendor="Palo Alto Networks",
        check=or_checks(
            check_header("server", "PanWeb", attack=False),
            check_header("x-pan-request-id", ".", attack=True),
            check_content("prisma.*cloud", attack=True),
            check_content("palo alto", attack=True),
            check_content("waas.*blocked", attack=True),
            check_content("twistlock", attack=True),
        ),
    )
