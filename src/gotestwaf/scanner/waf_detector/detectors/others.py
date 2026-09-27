"""Additional WAF detectors — CDNs, open-source, and niche vendors."""

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


# ── CDN / Edge WAFs ──

def fastly() -> Detector:
    return Detector(
        waf_name="Fastly WAF (Signal Sciences)",
        vendor="Fastly",
        check=or_checks(
            check_header("server", "Fastly", attack=False),
            check_header("x-fastly-request-id", ".", attack=False),
            check_header("via", "varnish", attack=False),
            check_content("fastly error", attack=True),
            check_content("signal sciences", attack=True),
        ),
    )


def edgecast_verizon() -> Detector:
    return Detector(
        waf_name="Edgio (Verizon Digital Media)",
        vendor="Edgio",
        check=or_checks(
            check_header("server", "ECAcc", attack=False),
            check_header("server", "ECS", attack=False),
            check_header("x-ec-custom-error", ".", attack=True),
            check_content("verizon digital media", attack=True),
        ),
    )


def stackpath() -> Detector:
    return Detector(
        waf_name="StackPath WAF",
        vendor="StackPath (HighWinds)",
        check=or_checks(
            check_header("x-sp-.*", ".", attack=False),
            check_header("server", "StackPath", attack=False),
            check_content("stackpath", attack=True),
            check_content("highwinds", attack=True),
        ),
    )


def keycdn() -> Detector:
    return Detector(
        waf_name="KeyCDN",
        vendor="proinity LLC",
        check=or_checks(
            check_header("server", "KeyCDN", attack=False),
            check_header("x-edge-location", ".", attack=False),
        ),
    )


# ── Reverse Proxy / Open Source WAFs ──

def nginx_naxsi() -> Detector:
    return Detector(
        waf_name="NAXSI",
        vendor="NBS System (nginx)",
        check=or_checks(
            check_header("server", "naxsi", attack=True),
            check_header("x-naxsi-sig", ".", attack=True),
            check_content("naxsi.*blocked", attack=True),
        ),
    )


def openresty_lua_waf() -> Detector:
    return Detector(
        waf_name="OpenResty / lua-resty-waf",
        vendor="OpenResty",
        check=or_checks(
            check_header("server", "openresty", attack=False),
            check_content("openresty", attack=True),
            check_content("lua.resty.waf", attack=True),
        ),
    )


def wallarm() -> Detector:
    return Detector(
        waf_name="Wallarm NGWAF",
        vendor="Wallarm Inc.",
        check=or_checks(
            check_header("server", "nginx-wallarm", attack=False),
            check_header("x-wallarm-.*", ".", attack=True),
            check_content("wallarm", attack=True),
        ),
    )


def reblaze() -> Detector:
    return Detector(
        waf_name="Reblaze",
        vendor="Reblaze Technologies",
        check=or_checks(
            check_header("server", "Reblaze", attack=False),
            check_cookie("rbzid", attack=False),
            check_content("reblaze", attack=True),
        ),
    )


def radware_appwall() -> Detector:
    return Detector(
        waf_name="AppWall",
        vendor="Radware",
        check=or_checks(
            check_header("x-sl-compstate", ".", attack=False),
            check_content("radware", attack=True),
            # Dropped: "unauthorized activity" — generic security phrasing
            # used by banking apps, enterprise portals, and many other
            # error templates. Not Radware-specific.
            check_content("appwall", attack=True),
        ),
    )


def denyall() -> Detector:
    return Detector(
        waf_name="DenyAll (Rohde & Schwarz)",
        vendor="Rohde & Schwarz",
        check=or_checks(
            check_header("server", "DenyAll", attack=False),
            check_cookie("sessioncookie", attack=False),
            check_content("denyall", attack=True),
            check_content("conditioned.*blocked", attack=True),
        ),
    )


def squarespace() -> Detector:
    return Detector(
        waf_name="Squarespace",
        vendor="Squarespace Inc.",
        check=or_checks(
            check_header("server", "Squarespace", attack=False),
            check_header("x-served-by", "squarespace", attack=False),
        ),
    )


def vercel() -> Detector:
    return Detector(
        waf_name="Vercel Firewall",
        vendor="Vercel",
        check=or_checks(
            check_header("server", "Vercel", attack=False),
            check_header("x-vercel-id", ".", attack=False),
            check_content("vercel", attack=True),
        ),
    )


def netlify() -> Detector:
    return Detector(
        waf_name="Netlify",
        vendor="Netlify Inc.",
        check=or_checks(
            check_header("server", "Netlify", attack=False),
            check_header("x-nf-request-id", ".", attack=False),
        ),
    )


# ── Enterprise / Niche WAFs ──

def sophos_utm() -> Detector:
    return Detector(
        waf_name="Sophos UTM WAF",
        vendor="Sophos",
        check=or_checks(
            check_header("server", "Sophos", attack=False),
            check_content("sophos", attack=True),
            check_content("utm.*web.*protection", attack=True),
        ),
    )


def comodo_waf() -> Detector:
    return Detector(
        waf_name="Comodo WAF",
        vendor="Comodo (Sectigo)",
        check=or_checks(
            check_header("server", "Comodo", attack=False),
            check_content("protected by comodo", attack=True),
            check_content("comodo waf", attack=True),
        ),
    )


def dosarrest() -> Detector:
    return Detector(
        waf_name="DOSarrest",
        vendor="DOSarrest Internet Security",
        check=or_checks(
            check_header("server", "DOSarrest", attack=False),
            check_header("x-dosarrest-.*", ".", attack=False),
            check_content("dosarrest", attack=True),
        ),
    )


def snapt() -> Detector:
    return Detector(
        waf_name="Snapt Aria",
        vendor="Snapt Inc.",
        check=or_checks(
            check_header("server", "Snapt", attack=False),
            check_content("snapt", attack=True),
        ),
    )


def armor_defense() -> Detector:
    return Detector(
        waf_name="Armor Defense",
        vendor="Armor",
        check=or_checks(
            check_header("server", "Armor", attack=False),
            check_content("armor", attack=True),
            check_content("blocked by armor", attack=True),
        ),
    )


def bekchy() -> Detector:
    return Detector(
        waf_name="Bekchy",
        vendor="Faydata Technologies",
        check=or_checks(
            check_content("bekchy.*blocked", attack=True),
            check_content("bekchy", attack=True),
        ),
    )


def safedog() -> Detector:
    return Detector(
        waf_name="SafeDog",
        vendor="SafeDog",
        check=or_checks(
            check_header("server", "SafeDog", attack=False),
            check_cookie("safedog-flow-item", attack=False),
            check_content("safedog", attack=True),
        ),
    )


def yunsuo() -> Detector:
    return Detector(
        waf_name="Yunsuo",
        vendor="Yunsuo",
        check=or_checks(
            check_cookie("yunsuo_session", attack=False),
            check_content("yunsuo", attack=True),
        ),
    )


def wangzhan_bao() -> Detector:
    return Detector(
        waf_name="Wangzhan Bao",
        vendor="ChinaCache",
        check=or_checks(
            check_header("x-powered-by-anquanbao", ".", attack=False),
            check_content("anquanbao", attack=True),
        ),
    )


def tencent_cloud_waf() -> Detector:
    return Detector(
        waf_name="Tencent Cloud WAF",
        vendor="Tencent",
        check=or_checks(
            check_header("server", "TencentCloud", attack=False),
            check_content("waf.tencent", attack=True),
            check_content("tencent cloud waf", attack=True),
        ),
    )


def alibaba_cloud_waf() -> Detector:
    return Detector(
        waf_name="Alibaba Cloud WAF",
        vendor="Alibaba Cloud",
        check=or_checks(
            check_header("server", "Tengine", attack=False),
            check_cookie("aliyungf_tc", attack=False),
            check_content("errors.aliyun.com", attack=True),
            check_content("alibaba cloud", attack=True),
        ),
    )


def huawei_cloud_waf() -> Detector:
    return Detector(
        waf_name="Huawei Cloud WAF",
        vendor="Huawei Cloud",
        check=or_checks(
            check_header("server", "HuaweiCloudWAF", attack=False),
            check_content("huawei cloud waf", attack=True),
            check_content("hwclouds", attack=True),
        ),
    )
