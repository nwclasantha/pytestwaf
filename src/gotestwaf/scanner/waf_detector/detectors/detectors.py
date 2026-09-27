"""WAF detector registry and Detector type."""

from __future__ import annotations

from dataclasses import dataclass

from gotestwaf.scanner.waf_detector.detectors.checks import Check, Responses


@dataclass(slots=True)
class Detector:
    """A WAF detector with name, vendor, and check functions.

    Two check functions serve different purposes:
    - is_waf_check: broad — "is this WAF present?" (used during identification)
    - check: specific — "did this WAF block THIS request?" (used during scanning)

    If is_waf_check is None, `check` is used for both purposes (legacy behavior).
    """

    waf_name: str
    vendor: str
    check: Check
    is_waf_check: Check | None = None

    def is_waf(self, resps: Responses) -> bool:
        if self.is_waf_check is not None:
            return self.is_waf_check(resps)
        return self.check(resps)


def _build_detectors() -> list[Detector]:
    """Build the list of all WAF detectors (50+)."""
    from gotestwaf.scanner.waf_detector.detectors.akamai import kona_site_defender
    from gotestwaf.scanner.waf_detector.detectors.aws import aws_cloudfront, aws_shield, aws_waf
    from gotestwaf.scanner.waf_detector.detectors.azure import azure_app_gateway, azure_front_door
    from gotestwaf.scanner.waf_detector.detectors.barracuda import barracuda_waf
    from gotestwaf.scanner.waf_detector.detectors.checkpoint import checkpoint_waf
    from gotestwaf.scanner.waf_detector.detectors.citrix import netscaler_appfw
    from gotestwaf.scanner.waf_detector.detectors.cloudflare import cloudflare
    from gotestwaf.scanner.waf_detector.detectors.f5networks import (
        bigip_ap_manager, bigip_app_sec_manager, bigip_local_traffic_manager,
        fire_pass, trafficshield,
    )
    from gotestwaf.scanner.waf_detector.detectors.fortinet import fortigate, fortiweb
    from gotestwaf.scanner.waf_detector.detectors.gcp import gcp_cloud_armor, gcp_cloud_cdn
    from gotestwaf.scanner.waf_detector.detectors.imperva import incapsula, secure_sphere
    from gotestwaf.scanner.waf_detector.detectors.modsec import mod_security
    from gotestwaf.scanner.waf_detector.detectors.others import (
        alibaba_cloud_waf, armor_defense, bekchy, comodo_waf, denyall,
        dosarrest, edgecast_verizon, fastly, huawei_cloud_waf, keycdn,
        netlify, nginx_naxsi, openresty_lua_waf, radware_appwall, reblaze,
        safedog, snapt, sophos_utm, squarespace, stackpath,
        tencent_cloud_waf, vercel, wallarm, wangzhan_bao, yunsuo,
    )
    from gotestwaf.scanner.waf_detector.detectors.paloalto import paloalto_prisma
    from gotestwaf.scanner.waf_detector.detectors.siteground import siteground_waf
    from gotestwaf.scanner.waf_detector.detectors.sucuri import sucuri_waf
    from gotestwaf.scanner.waf_detector.detectors.wordpress import wordfence, wp_cerber

    return [
        # Bot protection / hosting
        siteground_waf(),
        # Major CDN/WAF
        cloudflare(), kona_site_defender(), fastly(), edgecast_verizon(),
        stackpath(), keycdn(),
        # Cloud providers
        aws_waf(), aws_shield(), aws_cloudfront(),
        azure_front_door(), azure_app_gateway(),
        gcp_cloud_armor(), gcp_cloud_cdn(),
        alibaba_cloud_waf(), tencent_cloud_waf(), huawei_cloud_waf(),
        # Enterprise WAFs
        incapsula(), secure_sphere(),
        bigip_app_sec_manager(), bigip_local_traffic_manager(), bigip_ap_manager(),
        fire_pass(), trafficshield(),
        fortiweb(), fortigate(), barracuda_waf(), netscaler_appfw(),
        checkpoint_waf(), paloalto_prisma(), radware_appwall(), denyall(),
        # Open source / reverse proxy
        mod_security(), nginx_naxsi(), openresty_lua_waf(), wallarm(),
        # WordPress / CMS
        sucuri_waf(), wordfence(), wp_cerber(),
        # Hosting / PaaS
        squarespace(), vercel(), netlify(),
        # Niche / regional
        reblaze(), comodo_waf(), dosarrest(), snapt(), armor_defense(),
        bekchy(), sophos_utm(), safedog(), yunsuo(), wangzhan_bao(),
    ]


# Lazy singleton
_detectors: list[Detector] | None = None


def get_detectors() -> list[Detector]:
    """Return the list of all WAF detectors."""
    global _detectors
    if _detectors is None:
        _detectors = _build_detectors()
    return _detectors
