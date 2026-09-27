"""Automatic CAPTCHA/bot protection solver using headless Playwright.

Runs once at scan startup to solve JS challenges (SiteGround sgcaptcha,
Cloudflare challenges, etc.) and extracts session cookies for httpx.
"""

from __future__ import annotations

import asyncio

import structlog

logger = structlog.get_logger()

# Stealth init script to hide automation signals from bot detection
_STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
if (navigator.permissions) {
    const origQuery = navigator.permissions.query;
    navigator.permissions.query = (params) =>
        params.name === 'notifications'
            ? Promise.resolve({state: Notification.permission})
            : origQuery.call(navigator.permissions, params);
}
window.chrome = window.chrome || {};
window.chrome.runtime = window.chrome.runtime || {
    onMessage: {addListener: ()=>{}, removeListener: ()=>{}},
    sendMessage: ()=>{},
    connect: ()=>({onMessage: {addListener: ()=>{}}, postMessage: ()=>{}}),
};
Object.defineProperty(screen, 'width', {get: () => 1920});
Object.defineProperty(screen, 'height', {get: () => 1080});
"""

# Cloudflare challenge page markers
_CF_CHALLENGE_MARKERS = (
    "just a moment", "checking your browser", "enable javascript",
    "cf-browser-verification", "challenge-platform", "turnstile",
    "cf-chl-bypass", "managed challenge",
)


async def solve_captcha(target_url: str, timeout_seconds: int = 60) -> dict[str, str]:
    """Solve CAPTCHA/bot challenge and return session cookies.

    Args:
        target_url: URL to solve challenge for.
        timeout_seconds: Max seconds to wait for challenge.

    Returns:
        Dict of cookie name -> value. Empty if solve fails.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.debug("Playwright not installed, skipping CAPTCHA solve")
        return {}

    cookies: dict[str, str] = {}

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-infobars",
                    "--window-size=1920,1080",
                    "--disable-extensions",
                    "--lang=en-US,en",
                ],
            )
            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1920, "height": 1080},
                locale="en-US",
                timezone_id="America/New_York",
                extra_http_headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Sec-Ch-Ua": '"Chromium";v="131", "Not_A Brand";v="24"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                },
            )
            await context.add_init_script(_STEALTH_JS)
            page = await context.new_page()

            logger.info("Solving bot protection challenge", url=target_url)

            # Navigate — use domcontentloaded for better challenge detection
            try:
                await page.goto(target_url, wait_until="domcontentloaded", timeout=20000)
            except Exception:
                try:
                    await page.goto(target_url, wait_until="commit", timeout=15000)
                except Exception:
                    pass

            # Wait for challenge to solve by watching for:
            # 1. Cloudflare challenge markers disappear from page
            # 2. cf_clearance cookie appears
            # 3. SiteGround sgcaptcha URL/title clears
            # 4. New cookies appear
            initial_cookies = {c["name"] for c in await context.cookies()}
            solved = False

            # Fast-path: if the landing page shows no challenge markers at all,
            # there's nothing to wait for. Without this, targets that have no JS
            # challenge (e.g. AWS CloudFront 403, Azure Front Door) waste the
            # full timeout_seconds budget polling for cookies that never appear.
            try:
                initial_title = (await page.title()).lower()
                initial_content = (await page.content())[:5000].lower()
                initial_url = page.url
                no_challenge = (
                    not any(m in initial_content or m in initial_title for m in _CF_CHALLENGE_MARKERS)
                    and "sgcaptcha" not in initial_url
                    and "robot" not in initial_title
                )
                if no_challenge:
                    logger.info(
                        "No challenge markers on landing page — skipping wait loop",
                        title=initial_title[:50],
                    )
                    solved = True
            except Exception:
                pass

            for i in range(0 if solved else timeout_seconds):
                await asyncio.sleep(1)
                try:
                    title = (await page.title()).lower()
                    current_url = page.url

                    # Check for Cloudflare challenge page
                    is_cf_challenge = False
                    try:
                        page_content = (await page.content())[:5000].lower()
                        is_cf_challenge = any(
                            marker in page_content or marker in title
                            for marker in _CF_CHALLENGE_MARKERS
                        )
                    except Exception:
                        pass

                    # Check for SiteGround challenge
                    on_sg_challenge = "sgcaptcha" in current_url or "robot" in title

                    # Check for cf_clearance cookie (Cloudflare's session cookie)
                    current_cookies = {c["name"] for c in await context.cookies()}
                    has_clearance = "cf_clearance" in current_cookies

                    # Solved if cf_clearance appeared
                    if has_clearance and "cf_clearance" not in initial_cookies:
                        solved = True
                        logger.info("Challenge solved (cf_clearance obtained)", seconds=i + 1)
                        break

                    # Solved if we're past challenge pages
                    if not is_cf_challenge and not on_sg_challenge and i >= 5:
                        # Verify it's not just a block page that looks non-challenge
                        if has_clearance or len(current_cookies - initial_cookies) > 0:
                            solved = True
                            logger.info("Challenge solved", title=title[:50], seconds=i + 1)
                            break

                    # New cookies appeared (JS challenge completed)
                    new_cookies = current_cookies - initial_cookies
                    if new_cookies and i >= 3:
                        solved = True
                        logger.info(
                            "Challenge solved (new cookies)",
                            seconds=i + 1,
                            new_cookies=list(new_cookies)[:5],
                        )
                        break

                except Exception:
                    continue

                if i > 0 and i % 15 == 0:
                    logger.info("Still solving challenge", seconds=i)

            if not solved:
                logger.warning(
                    "Challenge timeout — extracting cookies anyway",
                    timeout=timeout_seconds,
                )
                # Try reloading once more
                try:
                    await page.reload(wait_until="domcontentloaded", timeout=15000)
                    await asyncio.sleep(5)
                except Exception:
                    pass

            # Wait for cookies to settle
            await asyncio.sleep(3)

            # Extract all cookies
            raw_cookies = await context.cookies()
            for c in raw_cookies:
                cookies[c["name"]] = c["value"]

            cf_cookies = [n for n in cookies if n.startswith("cf_") or n.startswith("__cf")]
            if cookies:
                logger.info("Extracted session cookies", count=len(cookies))
                if cf_cookies:
                    logger.info("Cloudflare cookies found", cookies=cf_cookies)
                elif not solved:
                    logger.warning(
                        "No Cloudflare cookies (cf_clearance) found — "
                        "bot-level blocking may still be active"
                    )
            else:
                logger.warning("No cookies extracted")

            try:
                await browser.close()
            except Exception:
                pass

    except Exception as e:  # noqa: BLE001
        logger.warning("CAPTCHA solver failed", error=str(e))
        # Force close browser if it exists. `'browser' in dir()` searched
        # the local scope object's attributes, not the local-variable namespace,
        # so it was effectively always-false here and any launched browser
        # would have leaked. `locals()` is the correct check.
        try:
            if "browser" in locals() and browser is not None:
                await browser.close()
        except Exception:
            pass

    return cookies
