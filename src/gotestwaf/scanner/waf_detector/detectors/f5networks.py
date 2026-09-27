"""F5 Networks WAF detectors."""

from __future__ import annotations

from gotestwaf.scanner.waf_detector.detectors.checks import (
    and_checks,
    check_content,
    check_cookie,
    check_header,
    or_checks,
)
from gotestwaf.scanner.waf_detector.detectors.detectors import Detector


def bigip_app_sec_manager() -> Detector:
    """Create F5 BIG-IP AppSec Manager detector."""
    return Detector(
        waf_name="BIG-IP AppSec Manager",
        vendor="F5 Networks",
        check=or_checks(
            and_checks(
                check_content("the requested url was rejected", attack=True),
                check_content("please consult with your administrator", attack=True),
            ),
            check_cookie(r"^TS.+?", attack=False),
            # Dropped: standalone `check_content("Reference ID")` — generic
            # phrase used by Incapsula, Akamai, support-ticket UIs, and
            # countless custom error pages. F5 block pages are already
            # covered by the and_checks clause above (rejected URL +
            # consult administrator).
        ),
    )


def bigip_local_traffic_manager() -> Detector:
    """Create F5 BIG-IP Local Traffic Manager detector."""
    return Detector(
        waf_name="BIG-IP Local Traffic Manager",
        vendor="F5 Networks",
        check=or_checks(
            check_cookie("^bigipserver", attack=False),
            check_header("X-Cnection", "close", attack=True),
        ),
    )


def bigip_ap_manager() -> Detector:
    """Create F5 BIG-IP AP Manager detector."""
    return Detector(
        waf_name="BIG-IP AP Manager",
        vendor="F5 Networks",
        check=or_checks(
            and_checks(
                check_cookie("^LastMRH_Session", attack=False),
                check_cookie("^MRHSession", attack=False),
            ),
            and_checks(
                check_cookie("^MRHSession", attack=False),
                check_header("Server", r"Big([-_])?IP", attack=True),
            ),
            or_checks(
                check_cookie("^F5_fullWT", attack=False),
                check_cookie("^F5_HT_shrinked", attack=False),
            ),
        ),
    )


def fire_pass() -> Detector:
    """Create F5 FirePass detector."""
    return Detector(
        waf_name="FirePass",
        vendor="F5 Networks",
        check=or_checks(
            and_checks(
                check_cookie("^VHOST", attack=False),
                check_header("Location", r"\/my\.logon\.php3", attack=False),
            ),
            and_checks(
                check_cookie(r"^F5_fire.+?", attack=False),
                check_cookie("^F5_passid_shrinked", attack=False),
            ),
        ),
    )


def trafficshield() -> Detector:
    """Create F5 Trafficshield detector."""
    return Detector(
        waf_name="Trafficshield",
        vendor="F5 Networks",
        check=or_checks(
            check_cookie("^ASINFO=", attack=False),
            check_header("Server", "F5-TrafficShield", attack=False),
        ),
    )
