"""Harvest session cookies by solving CAPTCHA in a visible browser.

Opens a real Chrome window. You solve the CAPTCHA manually.
The script auto-detects when the real site loads and saves cookies.
"""

import asyncio
import json
import sys
from pathlib import Path

from playwright.async_api import async_playwright


async def harvest(url: str, cookie_file: str = "session_cookies.json") -> None:
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=False,
            args=["--disable-blink-features=AutomationControlled"],
        )

        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            ),
        )

        page = await context.new_page()

        print(f"Opening {url} ...")
        print("=" * 60)
        print("A Chrome window will open.")
        print("SOLVE THE CAPTCHA in the browser window.")
        print("Script will auto-detect when the real site loads.")
        print("=" * 60)

        try:
            await page.goto(url, wait_until="commit", timeout=30000)
        except Exception:
            pass

        # Auto-detect when CAPTCHA is solved by polling
        for attempt in range(180):  # Wait up to 3 minutes
            await asyncio.sleep(1)

            try:
                current_url = page.url
                title = await page.title()
            except Exception:
                # Page navigating — wait
                if attempt % 5 == 0:
                    print(f"  Page navigating... ({attempt}s)")
                continue

            # Check if we're past the CAPTCHA
            is_captcha = any(
                kw in title.lower()
                for kw in ("captcha", "challenge", "robot", "verify", "checking")
            )
            is_captcha = is_captcha or "sgcaptcha" in current_url.lower()

            if not is_captcha and len(title) > 3:
                print(f"\n>>> Real site loaded!")
                print(f"    Title: {title}")
                print(f"    URL: {current_url}")
                break

            if attempt % 15 == 0 and attempt > 0:
                print(f"  Waiting for CAPTCHA solve... ({attempt}s) - {title[:50]}")

        else:
            print("\nTimeout (3 min). Saving cookies anyway...")

        # Wait for cookies to settle
        await asyncio.sleep(3)

        # Capture ALL cookies from context
        cookies = await context.cookies()
        print(f"\nCaptured {len(cookies)} cookies:")
        for c in cookies:
            print(f"  {c['name']} = {c['value'][:50]}{'...' if len(c['value']) > 50 else ''}")

        # Save cookies (restrict permissions since these may contain auth tokens)
        import os
        cookie_path = Path(cookie_file)
        cookie_path.write_text(json.dumps(cookies, indent=2))
        try:
            os.chmod(str(cookie_path), 0o600)
        except OSError:
            pass
        print(f"\nSaved to {cookie_file}")

        # Quick verification
        try:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=10000)
            status = resp.status if resp else 0
            await asyncio.sleep(2)
            title = await page.title()
            is_real = status == 200 and "captcha" not in title.lower()
            print(f"\nVerify: status={status}, title={title[:60]}")
            if is_real:
                print("\n" + "=" * 60)
                print("SUCCESS! Cookies valid. Run the scan now:")
                print(f"  cd {Path('.').resolve()}")
                print(f"  PYTHONPATH=src python -m gotestwaf \\")
                print(f"    --url={url} \\")
                print(f"    --workers=2 --sendDelay=600 --randomDelay=400 \\")
                print(f"    --noEmailReport --includePayloads \\")
                print(f"    --reportFormat=html --wafName=Cloudflare \\")
                print(f"    --reportName=kernernorland-real-waf-report")
                print("=" * 60)
            else:
                print("\nCookies captured but CAPTCHA may still be active.")
                print("The scan will try anyway — cookies might work for httpx.")
        except Exception as e:
            print(f"\nVerify failed: {e}")
            print("Cookies saved anyway — try the scan.")

        await browser.close()


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://kernernorland.com/"
    asyncio.run(harvest(url))
