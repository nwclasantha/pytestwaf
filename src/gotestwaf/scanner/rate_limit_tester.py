"""Rate limit testing — detects WAF rate limiting thresholds.

Sends increasing bursts of benign requests to find the point where
the WAF starts rate limiting (returning 429/503).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx
import structlog

if TYPE_CHECKING:
    from gotestwaf.config.config import Config

logger = structlog.get_logger()


@dataclass(slots=True)
class RateLimitResult:
    """Results from rate limit testing."""
    threshold_rps: int = 0
    burst_tolerance: int = 0
    response_code_at_limit: int = 0
    time_to_recovery_s: float = 0.0
    pattern: str = "none_detected"  # "hard_cutoff", "gradual", "none_detected"
    tested_rates: list[int] = field(default_factory=list)
    block_rates: list[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "threshold_rps": self.threshold_rps,
            "burst_tolerance": self.burst_tolerance,
            "response_code_at_limit": self.response_code_at_limit,
            "time_to_recovery_s": round(self.time_to_recovery_s, 1),
            "pattern": self.pattern,
            "tested_rates": self.tested_rates,
            "block_rates": [round(r, 2) for r in self.block_rates],
        }


async def test_rate_limits(cfg: Config) -> RateLimitResult:
    """Test WAF rate limiting by sending increasing request bursts.

    Tests: 5, 10, 20, 50, 100, 200 requests per second.
    For each rate, sends requests for 3 seconds and checks for 429/503 responses.
    """
    result = RateLimitResult()
    rates_to_test = [5, 10, 20, 50, 100, 200]
    block_codes = {429, 503}

    logger.info("Starting rate limit test", target=cfg.url)

    from gotestwaf.helpers.url import get_target_url_str
    target = get_target_url_str(cfg.url)

    async with httpx.AsyncClient(verify=cfg.tls_verify, timeout=10.0, follow_redirects=True) as client:
        headers = dict(cfg.http_headers)

        for rps in rates_to_test:
            logger.info(f"Testing {rps} requests/second...")
            statuses = await _send_burst(client, target, headers, rps, duration_s=3)

            blocked = sum(1 for s in statuses if s in block_codes)
            block_rate = blocked / len(statuses) if statuses else 0.0

            result.tested_rates.append(rps)
            result.block_rates.append(block_rate)

            logger.info(f"  {rps} RPS: {len(statuses)} sent, {blocked} rate-limited ({block_rate:.0%})")

            if block_rate > 0.5:
                # Rate limiting detected
                result.threshold_rps = rps
                result.response_code_at_limit = next((s for s in statuses if s in block_codes), 429)
                result.pattern = "hard_cutoff" if block_rate > 0.9 else "gradual"
                result.burst_tolerance = sum(1 for s in statuses if s not in block_codes)

                # Test recovery time
                result.time_to_recovery_s = await _test_recovery(client, target, headers, block_codes)

                logger.info(
                    "Rate limit detected",
                    threshold_rps=rps,
                    pattern=result.pattern,
                    recovery_s=f"{result.time_to_recovery_s:.1f}",
                )
                break

            # Brief pause between tests to avoid accumulation
            await asyncio.sleep(2)

    if not result.threshold_rps:
        result.pattern = "none_detected"
        logger.info("No rate limiting detected up to 200 RPS")

    return result


async def _send_burst(
    client: httpx.AsyncClient, url: str, headers: dict, rps: int, duration_s: int,
) -> list[int]:
    """Send `rps * duration_s` requests, paced one batch per second.

    Previously implemented as a single sequential await loop, which capped
    real throughput at the per-request latency (~5–20 RPS regardless of
    `rps`), silently making the rate-limit detection always report
    "no rate limiting detected" even for WAFs with tight limits. Now
    fires one concurrent batch per second using asyncio.gather so the
    advertised RPS is actually achieved.
    """
    statuses: list[int] = []

    async def _one_request() -> int:
        try:
            resp = await client.get(url, headers=headers)
            return resp.status_code
        except Exception:
            return 0

    for _ in range(duration_s):
        start = time.monotonic()
        results = await asyncio.gather(*[_one_request() for _ in range(rps)])
        statuses.extend(results)
        elapsed = time.monotonic() - start
        sleep_time = max(0.0, 1.0 - elapsed)
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)

    return statuses


async def _test_recovery(
    client: httpx.AsyncClient, url: str, headers: dict, block_codes: set,
) -> float:
    """After rate limiting, measure how long until requests pass again."""
    start = time.monotonic()
    for _ in range(60):  # Check every second for up to 60 seconds
        await asyncio.sleep(1)
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code not in block_codes:
                return time.monotonic() - start
        except Exception:
            continue
    return 60.0  # Didn't recover within 60 seconds
