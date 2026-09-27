"""Cloudflare WAF detector."""

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


def cloudflare() -> Detector:
    """Create Cloudflare WAF detector.

    IMPORTANT: The `check` function is used as `check_block_func` during
    scanning to determine if a SPECIFIC response was blocked by the WAF.
    It must ONLY match actual Cloudflare WAF block pages, NOT every
    response that passes through Cloudflare (which all have server: cloudflare).
    """
    return Detector(
        waf_name="Cloudflare",
        vendor="Cloudflare Inc.",
        # Detection: broad — "is Cloudflare present?"
        is_waf_check=or_checks(
            check_header("server", "cloudflare", attack=False),
            check_header("cf-ray", ".", attack=False),
            check_cookie("__cf_bm", attack=False),
            check_cookie("cf_clearance", attack=False),
        ),
        # Block check: specific — "did Cloudflare WAF block THIS request?"
        check=or_checks(
            # Cloudflare WAF block page (Error 1020)
            check_content("error 1020", attack=True),
            # Cloudflare "Attention Required" block page
            and_checks(
                check_content("attention required", attack=True),
                check_status_code(403, attack=True),
            ),
            # Cloudflare challenge/block with cf-mitigated header
            check_header("cf-mitigated", "challenge", attack=True),
            # Generic Cloudflare block (403 + cloudflare error page)
            and_checks(
                check_status_code(403, attack=True),
                check_content("cf-error", attack=True),
            ),
        ),
    )
