"""Session Manager — owns a persistent Playwright browser and refreshes cookies.

Solves the bot protection challenge once at startup, then runs a background
task that refreshes cookies every N minutes (configurable per bot type).
Provides fresh cookies to both httpx and Chrome clients.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import structlog

from gotestwaf.scanner.bot_detector import BotProtectionProfile, BotProtectionType

logger = structlog.get_logger()

SESSION_COOKIES_FILE = "session_cookies.json"

# Stealth script
_STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
window.chrome = window.chrome || {};
window.chrome.runtime = window.chrome.runtime || {
    onMessage: {addListener: ()=>{}, removeListener: ()=>{}},
    sendMessage: ()=>{},
};
"""


class SessionManager:
    """Manages a persistent browser session with automatic cookie refresh."""

    def __init__(
        self,
        target_url: str,
        profile: BotProtectionProfile,
        user_agent: str = "",
        tls_verify: bool = False,
    ) -> None:
        self._target_url = target_url
        self._profile = profile
        self._tls_verify = tls_verify
        self._user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        )

        self._pw: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None

        self._cookies: dict[str, str] = {}
        self._lock = asyncio.Lock()
        self._solve_lock = asyncio.Lock()  # Prevents concurrent _solve_challenge
        self._refresh_task: asyncio.Task | None = None
        self._started = False
        self._challenge_solved = False

    async def start(self) -> None:
        """Launch browser, solve initial challenge, start refresh loop."""
        if self._started:
            return
        self._started = True  # Set FIRST to prevent re-entry

        from playwright.async_api import async_playwright

        self._pw = await async_playwright().start()

        launch_args = [
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-infobars",
            "--window-size=1920,1080",
            "--lang=en-US,en",
        ]
        if not self._tls_verify:
            launch_args.extend(["--ignore-certificate-errors", "--allow-insecure-localhost"])

        self._browser = await self._pw.chromium.launch(
            headless=True, args=launch_args,
        )
        self._context = await self._browser.new_context(
            user_agent=self._user_agent,
            viewport={"width": 1920, "height": 1080},
            locale="en-US",
            ignore_https_errors=not self._tls_verify,
            extra_http_headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Sec-Ch-Ua": '"Chromium";v="131", "Not_A Brand";v="24"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
            },
        )
        await self._context.add_init_script(_STEALTH_JS)
        self._page = await self._context.new_page()

        # Solve initial challenge
        await self._solve_challenge()

        # Start background refresh if interval > 0
        if self._profile.cookie_refresh_interval > 0:
            self._refresh_task = asyncio.create_task(self._refresh_loop())
            logger.info("Session manager: background refresh started",
                        interval_seconds=self._profile.cookie_refresh_interval)

    async def _solve_challenge(self) -> None:
        """Navigate to target and solve any bot protection challenge."""
        async with self._solve_lock:
            await self._solve_challenge_inner()

    async def _solve_challenge_inner(self) -> None:
        """Inner challenge solving logic (called under _solve_lock)."""
        logger.info("Session manager: solving challenge", url=self._target_url)

        try:
            await self._page.goto(self._target_url, wait_until="domcontentloaded", timeout=30000)
        except Exception:
            try:
                await self._page.goto(self._target_url, wait_until="commit", timeout=15000)
            except Exception:
                pass

        # Wait for challenge to solve
        timeout = self._profile.challenge_timeout_seconds
        initial_cookies = {c["name"] for c in await self._context.cookies()}
        target_cookies = set(self._profile.challenge_cookie_names)

        for i in range(timeout):
            await asyncio.sleep(1)
            try:
                title = (await self._page.title()).lower()
                content = (await self._page.content())[:3000].lower()

                # Check if still on challenge page (profile markers + universal markers)
                universal_markers = ("robot", "captcha", "sgcaptcha",
                                    "verify you are human", "challenge-platform",
                                    "just a moment", "checking your browser")
                all_markers = list(self._profile.challenge_markers) + list(universal_markers)
                is_challenge = any(m in title or m in content for m in all_markers)

                if is_challenge:
                    # Try clicking buttons/checkboxes
                    if i in (5, 15, 25):
                        try:
                            for sel in ["input[type='checkbox']", "button",
                                       ".challenge-form input[type='submit']"]:
                                el = await self._page.query_selector(sel)
                                if el and await el.is_visible():
                                    await el.click()
                                    await asyncio.sleep(2)
                                    break
                        except Exception:
                            pass
                    if i % 10 == 0 and i > 0:
                        logger.info("Session manager: still solving", seconds=i)
                    continue

                # Challenge gone — check cookies
                current_cookies = {c["name"] for c in await self._context.cookies()}
                new_cookies = current_cookies - initial_cookies

                # Check for target cookies
                if target_cookies and (target_cookies & current_cookies):
                    self._challenge_solved = True
                    logger.info("Session manager: challenge solved (target cookie found)",
                                seconds=i + 1, cookies=list(target_cookies & current_cookies))
                    break
                elif new_cookies and i >= 3:
                    self._challenge_solved = True
                    logger.info("Session manager: challenge solved (new cookies)",
                                seconds=i + 1, cookies=list(new_cookies)[:5])
                    break
                elif i >= 5 and not is_challenge:
                    self._challenge_solved = True
                    logger.info("Session manager: page loaded (no challenge)",
                                seconds=i + 1, title=title[:40])
                    break

            except Exception:
                continue

        if not self._challenge_solved:
            logger.warning("Session manager: challenge timeout, extracting cookies anyway",
                           timeout=timeout)

        await asyncio.sleep(2)

        # Extract cookies
        await self._extract_cookies()

    async def _extract_cookies(self) -> None:
        """Extract cookies from browser context and save to file."""
        async with self._lock:
            raw_cookies = await self._context.cookies()
            self._cookies = {}
            for c in raw_cookies:
                self._cookies[c["name"]] = c["value"]

            if self._cookies:
                # Save to file for httpx client
                cookie_list = [{"name": k, "value": v} for k, v in self._cookies.items()]
                Path(SESSION_COOKIES_FILE).write_text(
                    json.dumps(cookie_list, indent=2), encoding="utf-8"
                )
                logger.info("Session manager: cookies extracted", count=len(self._cookies))

    async def _refresh_loop(self) -> None:
        """Background task that periodically refreshes cookies."""
        interval = self._profile.cookie_refresh_interval
        while True:
            try:
                await asyncio.sleep(interval)
                logger.info("Session manager: refreshing cookies")
                await self._solve_challenge()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("Session manager: refresh failed", error=str(e))
                await asyncio.sleep(60)  # Wait 1 min before retry

    async def get_cookies(self) -> dict[str, str]:
        """Get current cookies (thread-safe)."""
        async with self._lock:
            return dict(self._cookies)

    async def force_refresh(self) -> None:
        """Force immediate cookie refresh (called when session expires)."""
        logger.warning("Session manager: forced refresh triggered")
        await self._solve_challenge()

    def get_context(self) -> Any:
        """Get the browser context for Chrome client to share."""
        return self._context

    def get_page(self) -> Any:
        """Get the main page for Chrome client fetch() calls."""
        return self._page

    def is_challenge_solved(self) -> bool:
        """Check if the initial challenge was solved."""
        return self._challenge_solved

    async def stop(self) -> None:
        """Stop refresh loop and close browser."""
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass

        # Null handles BEFORE closing the browser so that any concurrent
        # caller of get_context() / get_page() during shutdown receives
        # a clean None instead of a handle to a closed object (which raises
        # an opaque TargetClosedError on next use). Closing the browser
        # tears down the page and context implicitly.
        self._page = None
        self._context = None

        try:
            if self._browser:
                await self._browser.close()
        except Exception:
            pass
        self._browser = None
        try:
            if self._pw:
                await self._pw.stop()
        except Exception:
            pass
        self._pw = None

        self._started = False
        logger.info("Session manager: stopped")
