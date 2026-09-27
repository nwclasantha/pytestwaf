"""Bot protection type detection.

Fingerprints the target URL to identify what bot protection is in front
of the WAF (Cloudflare, SiteGround, AWS WAF, Imperva, etc.) and returns
a per-type configuration profile with tuned timeouts and delays.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

import structlog

logger = structlog.get_logger()


class BotProtectionType(Enum):
    """Types of bot protection systems."""
    NONE = "none"
    CLOUDFLARE = "cloudflare"
    SITEGROUND = "siteground"
    AWS_WAF = "aws_waf"
    IMPERVA = "imperva"
    AKAMAI = "akamai"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class BotProtectionProfile:
    """Per-type configuration for bot protection bypass."""
    protection_type: BotProtectionType = BotProtectionType.NONE
    name: str = "No Protection"
    challenge_cookie_names: list[str] = field(default_factory=list)
    challenge_timeout_seconds: int = 15
    cookie_refresh_interval: int = 1200  # 20 min
    recommended_delay_ms: int = 400
    challenge_markers: list[str] = field(default_factory=list)
    block_status_codes: list[int] = field(default_factory=lambda: [403])


# Pre-built profiles for each bot protection type
_PROFILES: dict[BotProtectionType, BotProtectionProfile] = {
    BotProtectionType.NONE: BotProtectionProfile(
        protection_type=BotProtectionType.NONE,
        name="No Protection",
        challenge_cookie_names=[],
        challenge_timeout_seconds=5,
        cookie_refresh_interval=0,  # No refresh needed
        recommended_delay_ms=100,  # Fast scanning
        challenge_markers=[],
        block_status_codes=[403],
    ),
    BotProtectionType.CLOUDFLARE: BotProtectionProfile(
        protection_type=BotProtectionType.CLOUDFLARE,
        name="Cloudflare",
        challenge_cookie_names=["cf_clearance", "__cf_bm"],
        challenge_timeout_seconds=20,
        cookie_refresh_interval=1200,  # 20 min (cf_clearance lasts ~30 min)
        recommended_delay_ms=500,
        challenge_markers=["just a moment", "checking your browser",
                          "cf-browser-verification", "challenge-platform",
                          "turnstile", "ray id"],
        block_status_codes=[403, 503],
    ),
    BotProtectionType.SITEGROUND: BotProtectionProfile(
        protection_type=BotProtectionType.SITEGROUND,
        name="SiteGround Security",
        challenge_cookie_names=["_I_", "sg_cookies_test"],
        challenge_timeout_seconds=30,
        cookie_refresh_interval=1800,  # 30 min
        recommended_delay_ms=300,
        challenge_markers=["sgcaptcha", "robot challenge", "sg-captcha"],
        block_status_codes=[202, 403],
    ),
    BotProtectionType.AWS_WAF: BotProtectionProfile(
        protection_type=BotProtectionType.AWS_WAF,
        name="AWS WAF",
        challenge_cookie_names=["aws-waf-token"],
        challenge_timeout_seconds=15,
        cookie_refresh_interval=1800,
        recommended_delay_ms=400,
        challenge_markers=["aws-waf", "captcha", "awswaf"],
        block_status_codes=[403],
    ),
    BotProtectionType.IMPERVA: BotProtectionProfile(
        protection_type=BotProtectionType.IMPERVA,
        name="Imperva/Incapsula",
        challenge_cookie_names=["incap_ses", "visid_incap", "reese84"],
        challenge_timeout_seconds=20,
        cookie_refresh_interval=900,  # 15 min
        recommended_delay_ms=600,
        challenge_markers=["incapsula", "imperva", "reese84",
                          "_Incapsula_Resource"],
        block_status_codes=[403],
    ),
    BotProtectionType.AKAMAI: BotProtectionProfile(
        protection_type=BotProtectionType.AKAMAI,
        name="Akamai Bot Manager",
        challenge_cookie_names=["_abck", "ak_bmsc", "bm_sz"],
        challenge_timeout_seconds=15,
        cookie_refresh_interval=600,  # 10 min
        recommended_delay_ms=500,
        challenge_markers=["akamai", "_abck", "ak_bmsc"],
        block_status_codes=[403],
    ),
    BotProtectionType.UNKNOWN: BotProtectionProfile(
        protection_type=BotProtectionType.UNKNOWN,
        name="Unknown Bot Protection",
        challenge_cookie_names=[],
        challenge_timeout_seconds=30,
        cookie_refresh_interval=1200,
        recommended_delay_ms=500,
        challenge_markers=[],
        block_status_codes=[403],
    ),
}


async def detect_bot_protection(
    url: str,
    tls_verify: bool = False,
) -> BotProtectionProfile:
    """Detect what bot protection is in front of the target.

    Makes one quick HTTP GET request without cookies to see what
    the raw response looks like. Fingerprints headers and body
    to identify the protection type.

    Args:
        url: Target URL to check.
        tls_verify: Whether to verify TLS certificates.

    Returns:
        BotProtectionProfile with per-type settings.
    """
    import httpx

    try:
        async with httpx.AsyncClient(
            timeout=15, follow_redirects=True, verify=tls_verify,
        ) as client:
            resp = await client.get(url)

        status = resp.status_code
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body = resp.text[:3000].lower()
        server = headers.get("server", "")

        # ── Cloudflare ──
        if "cloudflare" in server or "cf-ray" in headers:
            detected = BotProtectionType.CLOUDFLARE
            if status in (200, 301, 302) and "just a moment" not in body:
                # Cloudflare CDN but no challenge active
                logger.info("Bot protection: Cloudflare CDN detected (no active challenge)",
                            status=status)
                return _PROFILES[BotProtectionType.NONE]._replace_name("Cloudflare CDN (no challenge)")
            logger.info("Bot protection: Cloudflare with active challenge", status=status)
            return _PROFILES[BotProtectionType.CLOUDFLARE]

        # ── SiteGround ──
        if (headers.get("sg-captcha") == "challenge"
                or status == 202
                or "sgcaptcha" in body
                or "robot challenge" in body):
            logger.info("Bot protection: SiteGround Security detected", status=status)
            return _PROFILES[BotProtectionType.SITEGROUND]

        # ── AWS WAF ──
        # Only treat as AWS_WAF (which triggers a 15s browser challenge wait)
        # when actual challenge tokens are present in the body or headers.
        # Plain CloudFront / S3 hosts can return 403/404 for benign reasons
        # (origin missing, ACL block) without any AWS WAF involvement, and
        # waiting on a non-existent challenge wastes scan time.
        is_aws_infra = (
            "awselb" in server
            or "amazons3" in server
            or "cloudfront" in server
            or "x-amzn-waf" in " ".join(headers.keys())
            or "aws-waf" in body
        )
        if is_aws_infra:
            has_waf_challenge = (
                "aws-waf-token" in body
                or "awswaf" in body
                or "captcha" in body
                or "challenge" in body
                or "x-amzn-waf" in " ".join(headers.keys())
            )
            if status in (200, 301, 302) or not has_waf_challenge:
                logger.info("Bot protection: AWS infra detected, no active challenge",
                            status=status)
                return _PROFILES[BotProtectionType.NONE]
            logger.info("Bot protection: AWS WAF with active challenge", status=status)
            return _PROFILES[BotProtectionType.AWS_WAF]

        # ── Imperva/Incapsula ──
        if ("incapsula" in body or "imperva" in body
                or "visid_incap" in headers.get("set-cookie", "")
                or "x-iinfo" in headers):
            logger.info("Bot protection: Imperva/Incapsula detected", status=status)
            return _PROFILES[BotProtectionType.IMPERVA]

        # ── Akamai ──
        if ("akamai" in server or "_abck" in headers.get("set-cookie", "")
                or "ak_bmsc" in headers.get("set-cookie", "")):
            logger.info("Bot protection: Akamai detected", status=status)
            return _PROFILES[BotProtectionType.AKAMAI]

        # ── No protection detected ──
        if status in (200, 301, 302, 404):
            logger.info("Bot protection: None detected", status=status)
            return _PROFILES[BotProtectionType.NONE]

        # ── Unknown protection ──
        if status in (403, 406, 429, 503):
            logger.info("Bot protection: Unknown (blocked with no markers)", status=status)
            return _PROFILES[BotProtectionType.UNKNOWN]

        logger.info("Bot protection: None detected (default)", status=status)
        return _PROFILES[BotProtectionType.NONE]

    except Exception as e:
        logger.warning("Bot protection detection failed, assuming unknown", error=str(e))
        return _PROFILES[BotProtectionType.UNKNOWN]


def _replace_name(profile: BotProtectionProfile, name: str) -> BotProtectionProfile:
    """Helper to create a copy with a different name."""
    import copy
    p = copy.deepcopy(profile)
    p.name = name
    return p


# Monkey-patch for the _replace_name call above
BotProtectionProfile._replace_name = lambda self, name: _replace_name(self, name)
