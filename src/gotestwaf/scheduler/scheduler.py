"""Scheduled scanning — runs scans on a cron schedule with alerting.

Usage: gotestwaf --url=https://target.com --schedule="0 2 * * *" --threshold=80
Runs scan daily at 2am, alerts if score drops below 80%.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from gotestwaf.config.config import Config

logger = structlog.get_logger()


async def run_scheduled(cfg: Config, run_func, log_format: str, is_include_payloads_flag_used: bool) -> None:
    """Run scans on a cron schedule.

    Args:
        cfg: Scanner configuration.
        run_func: The async _run() function to call for each scan.
        log_format: Log format string.
        is_include_payloads_flag_used: Whether --includePayloads was explicitly set.
    """
    try:
        from croniter import croniter
    except ImportError:
        logger.error("croniter not installed. Run: pip install croniter")
        return

    cron = croniter(cfg.schedule, datetime.now())
    logger.info("Scheduled scanning enabled", schedule=cfg.schedule, threshold=cfg.threshold)

    scan_count = 0
    while True:
        next_run = cron.get_next(datetime)
        wait_seconds = (next_run - datetime.now()).total_seconds()

        if wait_seconds > 0:
            logger.info("Next scan scheduled", at=next_run.strftime("%Y-%m-%d %H:%M:%S"), wait=f"{wait_seconds:.0f}s")
            await asyncio.sleep(wait_seconds)

        scan_count += 1
        logger.info(f"Starting scheduled scan #{scan_count}")

        try:
            await run_func(cfg, log_format, is_include_payloads_flag_used)
        except Exception as e:
            logger.error("Scheduled scan failed", error=str(e))
            continue

        # Check threshold and alert
        if cfg.threshold > 0:
            try:
                from gotestwaf.ml.model_store import load_scan_knowledge
                knowledge = load_scan_knowledge(cfg.waf_name)
                if knowledge:
                    score = knowledge.get("scan_score", knowledge.get("model_metrics", {}).get("cv_f1", 0) * 100)
                    if score < cfg.threshold:
                        logger.warning(
                            "Score below threshold!",
                            score=f"{score:.1f}%",
                            threshold=f"{cfg.threshold:.1f}%",
                        )
                        # Send notifications if configured
                        if cfg.slack_webhook or cfg.teams_webhook:
                            logger.info("Sending threshold alert notifications...")
                            try:
                                from gotestwaf.db.statistics import Statistics
                                from gotestwaf.helpers.notifications import send_slack_notification, send_teams_notification
                                # Build minimal stat object for notification
                                stat = knowledge.get("_last_stat")
                                if cfg.slack_webhook and stat:
                                    await send_slack_notification(cfg.slack_webhook, stat, cfg.waf_name, cfg.url, [])
                                if cfg.teams_webhook and stat:
                                    await send_teams_notification(cfg.teams_webhook, stat, cfg.waf_name, cfg.url, [])
                            except Exception as notify_err:
                                logger.warning("Alert notification failed", error=str(notify_err))
            except Exception as e:
                logger.warning("Threshold check failed", error=str(e))
