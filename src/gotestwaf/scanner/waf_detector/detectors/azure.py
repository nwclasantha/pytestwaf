"""Microsoft Azure WAF detectors."""

from __future__ import annotations

from gotestwaf.scanner.waf_detector.detectors.checks import (
    check_content,
    check_cookie,
    check_header,
    or_checks,
)
from gotestwaf.scanner.waf_detector.detectors.detectors import Detector


def azure_front_door() -> Detector:
    # Detection patterns must be specific enough that they do NOT match a
    # benign HTML page. Azure FD's distinctive markers are the `x-azure-ref`
    # header and the literal "azure front door" string in block pages.
    # The previous `ref.*#[0-9a-f]+` content pattern matched generic
    # `<a href="#hash">` anchors and `<link href="...hash.css">` tags in any
    # HTML page — causing every benign 200 response to be classified as
    # "blocked" by `check_block_func` and zeroing the True-Negative score.
    return Detector(
        waf_name="Azure Front Door",
        vendor="Microsoft",
        check=or_checks(
            check_header("x-azure-ref", ".", attack=False),
            check_header("x-azure-ref", ".", attack=True),
            check_header("x-fd-healthprobe", ".", attack=False),
            check_header("x-ms-forbidden-ip", ".", attack=True),
            check_content("azure front door", attack=True),
        ),
    )


def azure_app_gateway() -> Detector:
    return Detector(
        waf_name="Azure Application Gateway",
        vendor="Microsoft",
        check=or_checks(
            check_header("server", "Microsoft-Azure-Application-Gateway", attack=False),
            check_header("x-ms-request-id", ".", attack=True),
            check_content("microsoft-azure-application-gateway", attack=True),
            check_content("403 - forbidden.*azure", attack=True),
        ),
    )
