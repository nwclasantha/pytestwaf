"""Slack and Microsoft Teams notifications for scan results."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx
import structlog

if TYPE_CHECKING:
    from gotestwaf.db.statistics import Statistics

logger = structlog.get_logger()


async def send_slack_notification(
    webhook_url: str, stat: Statistics, waf_name: str, url: str, report_files: list[str],
) -> None:
    """Send scan summary to Slack via incoming webhook."""
    tp = stat.true_positive_tests
    raw_score = stat.score.average
    score = max(0.0, raw_score)
    blocked = tp.req_stats.blocked_requests_number
    bypassed = tp.req_stats.bypassed_requests_number
    total = tp.req_stats.all_requests_number
    score_emoji = ":white_check_mark:" if score >= 80 else ":warning:" if score >= 50 else ":x:"

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{score_emoji} WAF Scan Complete — {waf_name}"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Target:*\n{url}"},
            {"type": "mrkdwn", "text": f"*Score:*\n{score:.1f}%"},
            {"type": "mrkdwn", "text": f"*Blocked:*\n{blocked}/{total}"},
            {"type": "mrkdwn", "text": f"*Bypassed:*\n{bypassed}/{total}"},
        ]},
        {"type": "section", "text": {"type": "mrkdwn",
            "text": f"*Reports:* {', '.join(f'`{f}`' for f in report_files[:3])}"}},
    ]

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(webhook_url, json={"blocks": blocks})
            if resp.status_code == 200:
                logger.info("Slack notification sent")
            else:
                logger.warning("Slack notification failed", status=resp.status_code)
    except Exception as e:
        logger.warning("Slack notification error", error=str(e))


async def send_teams_notification(
    webhook_url: str, stat: Statistics, waf_name: str, url: str, report_files: list[str],
) -> None:
    """Send scan summary to Microsoft Teams via incoming webhook."""
    tp = stat.true_positive_tests
    raw_score = stat.score.average
    score = max(0.0, raw_score)
    blocked = tp.req_stats.blocked_requests_number
    bypassed = tp.req_stats.bypassed_requests_number

    color = "00FF00" if score >= 80 else "FFA500" if score >= 50 else "FF0000"

    card = {
        "@type": "MessageCard", "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": f"WAF Scan: {waf_name} — {score:.1f}%",
        "sections": [{
            "activityTitle": f"WAF Scan Complete — {waf_name}",
            "activitySubtitle": url,
            "facts": [
                {"name": "Score", "value": f"{score:.1f}%"},
                {"name": "Blocked", "value": str(blocked)},
                {"name": "Bypassed", "value": str(bypassed)},
                {"name": "WAF", "value": waf_name},
            ],
            "markdown": True,
        }],
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(webhook_url, json=card)
            if resp.status_code == 200:
                logger.info("Teams notification sent")
            else:
                logger.warning("Teams notification failed", status=resp.status_code)
    except Exception as e:
        logger.warning("Teams notification error", error=str(e))
