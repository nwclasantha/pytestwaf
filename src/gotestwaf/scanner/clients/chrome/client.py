"""Chrome/Playwright-based HTTP client for WAF testing.

Uses fetch() from a solved browser page for ALL requests (GET and POST).
Optionally receives a SessionManager that owns the browser lifecycle
and refreshes cookies automatically in the background.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog

from gotestwaf.config.config import Config
from gotestwaf.helpers.utils import deep_copy_map
from gotestwaf.payload.payload import PayloadInfo
from gotestwaf.scanner.clients import GTW_DEBUG_HEADER
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest, Request
from gotestwaf.scanner.types.response import Response, ResponseMeta

logger = structlog.get_logger()


def _js_escape(s: str) -> str:
    """Escape a string for safe embedding in JavaScript using JSON serialization."""
    return json.dumps(s)


class Client:
    """Playwright-based HTTP client using fetch() from a solved page.

    All requests (GET and POST) use fetch() from the persistent solved page.
    No new page creation per request — fast and session-consistent.
    """

    def __init__(self, cfg: Config, session_mgr: Any = None, use_navigation: bool = False) -> None:
        self._headers = deep_copy_map(cfg.http_headers)
        for k in list(self._headers.keys()):
            if k.lower() == "host":
                del self._headers[k]
                break

        custom_header_parts = cfg.add_header.split(":", 1)
        if len(custom_header_parts) > 1:
            self._headers[custom_header_parts[0].strip()] = custom_header_parts[1].strip()

        self._target_url = cfg.url
        self._tls_verify = cfg.tls_verify
        self._session_mgr = session_mgr
        self._use_navigation = use_navigation  # Use page.goto() per request for bot-protected sites
        self._page = None
        self._pw = None
        self._browser = None
        self._context = None
        self._fetch_lock = asyncio.Semaphore(3)
        self._consecutive_failures = 0
        self._standalone_init = False

    async def _ensure_standalone(self) -> None:
        """Initialize standalone browser if no session_mgr provided."""
        if self._session_mgr or self._standalone_init:
            return
        self._standalone_init = True
        from playwright.async_api import async_playwright
        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled", "--no-sandbox",
                  "--disable-dev-shm-usage", "--lang=en-US,en"],
        )
        self._context = await self._browser.new_context(
            user_agent=self._headers.get("User-Agent", "Mozilla/5.0 Chrome/131.0.0.0"),
            ignore_https_errors=not self._tls_verify,
        )
        self._page = await self._context.new_page()
        try:
            await self._page.goto(self._target_url, wait_until="domcontentloaded", timeout=30000)
        except Exception:
            try:
                await self._page.goto(self._target_url, wait_until="commit", timeout=15000)
            except Exception:
                pass
        await asyncio.sleep(2)
        logger.info("Chrome client: standalone browser ready")

    async def _get_page(self) -> Any:
        """Get the page to use for fetch() calls."""
        if self._session_mgr:
            return self._session_mgr.get_page()
        await self._ensure_standalone()
        return self._page

    async def _execute_fetch(self, url: str, method: str, headers: dict[str, str],
                              body: str | None = None) -> dict[str, Any]:
        """Execute fetch() on the solved page."""
        page = await self._get_page()
        if page is None:
            return {"status": 0, "body": "", "headers": {}, "error": "no page available"}

        fetch_options: dict[str, Any] = {
            "method": method,
            "credentials": "include",
        }
        if headers:
            safe_headers = {k: v for k, v in headers.items()
                           if k.lower() not in ("host", "content-length", "connection")}
            if safe_headers:
                fetch_options["headers"] = safe_headers
        if body:
            fetch_options["body"] = body

        safe_url = _js_escape(url)
        safe_options = json.dumps(fetch_options)  # Valid JS object literal

        script = f"""
        async () => {{
            try {{
                const opts = {safe_options};
                const resp = await fetch({safe_url}, opts);
                const body = await resp.text();
                const hdrs = {{}};
                resp.headers.forEach((v, k) => {{ hdrs[k] = v; }});
                return {{
                    status: resp.status,
                    statusText: resp.statusText,
                    body: body.substring(0, 50000),
                    headers: hdrs,
                }};
            }} catch(e) {{
                return {{status: 0, statusText: "", body: "", headers: {{}}, error: e.message}};
            }}
        }}
        """
        async with self._fetch_lock:
            try:
                result = await page.evaluate(script)

                # Track consecutive failures for session refresh
                if result.get("status", 0) in (202, 503) or result.get("error"):
                    self._consecutive_failures += 1
                    # After 10 consecutive failures, force refresh
                    if self._consecutive_failures >= 10 and self._session_mgr:
                        self._consecutive_failures = 0
                        logger.warning("Chrome client: 10 consecutive failures, refreshing session")
                        await self._session_mgr.force_refresh()
                        # Re-fetch page: force_refresh may have created a new
                        # browser page, making our captured `page` stale.
                        page = await self._get_page()
                        if page is None:
                            return {"status": 0, "body": "", "headers": {}, "error": "page unavailable after refresh"}
                        return await page.evaluate(script)
                else:
                    self._consecutive_failures = 0

                return result
            except Exception as e:
                # Page context may be destroyed — try to recover
                if self._session_mgr:
                    try:
                        await self._session_mgr.force_refresh()
                        page = await self._get_page()
                        return await page.evaluate(script)
                    except Exception:
                        pass
                return {"status": 0, "body": "", "headers": {}, "error": str(e)}

    async def _navigate_fetch(self, url: str, method: str, headers: dict[str, str],
                              body: str | None = None) -> dict[str, Any]:
        """Navigate directly to payload URL on a new page.

        Each request gets its own page. The browser navigates to the
        payload URL, solves any challenge automatically, and returns
        the final response. The response body is used for Jaccard
        comparison to distinguish WAF blocks from generic blocks.
        """
        context = self._session_mgr.get_context() if self._session_mgr else self._context
        if context is None:
            return {"status": 0, "body": "", "headers": {}, "error": "no context"}

        # Hold the semaphore across the FULL navigation/evaluate lifecycle.
        # The previous version released the lock right after `new_page()`,
        # so unlimited concurrent navigations could pile up against Chromium
        # — defeating the purpose of `_fetch_lock` and causing OOM/crashes
        # on large scans.
        async with self._fetch_lock:
            page = await context.new_page()
            try:
                if method.upper() == "GET" and not body:
                    # Navigate directly to the payload URL
                    try:
                        resp = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    except Exception:
                        try:
                            resp = await page.goto(url, wait_until="commit", timeout=10000)
                        except Exception as e:
                            return {"status": 0, "body": "", "headers": {}, "error": str(e)}

                    if resp is None:
                        return {"status": 0, "body": "", "headers": {}, "error": "no response"}

                    status = resp.status
                    resp_headers = {}
                    try:
                        for k, v in resp.headers.items():
                            resp_headers[k.lower()] = v
                    except Exception:
                        pass

                    # Get response body for Jaccard comparison
                    page_body = ""
                    try:
                        raw = await resp.body()
                        if raw:
                            page_body = raw.decode("utf-8", errors="replace")
                    except Exception:
                        pass
                    if not page_body or len(page_body) < 50:
                        try:
                            page_body = await page.content()
                        except Exception:
                            pass

                    return {"status": status, "statusText": "", "body": page_body[:5000], "headers": resp_headers}
                else:
                    # POST: navigate to base first, then fetch()
                    try:
                        await page.goto(self._target_url, wait_until="commit", timeout=10000)
                    except Exception:
                        pass
                    await asyncio.sleep(0.3)

                    fetch_options: dict[str, Any] = {"method": method, "credentials": "include"}
                    if headers:
                        safe = {k: v for k, v in headers.items()
                               if k.lower() not in ("host", "content-length", "connection")}
                        if safe:
                            fetch_options["headers"] = safe
                    if body:
                        fetch_options["body"] = body

                    safe_url = _js_escape(url)
                    safe_options = json.dumps(fetch_options)
                    script = f"""
                    async () => {{
                        try {{
                            const opts = {safe_options};
                            const resp = await fetch({safe_url}, opts);
                            const body = await resp.text();
                            const hdrs = {{}};
                            resp.headers.forEach((v, k) => {{ hdrs[k] = v; }});
                            return {{status: resp.status, statusText: resp.statusText,
                                    body: body.substring(0, 50000), headers: hdrs}};
                        }} catch(e) {{
                            return {{status: 0, statusText: "", body: "", headers: {{}}, error: e.message}};
                        }}
                    }}
                    """
                    try:
                        return await page.evaluate(script)
                    except Exception as e:
                        return {"status": 0, "body": "", "headers": {}, "error": str(e)}
            finally:
                try:
                    await page.close()
                except Exception:
                    pass

    def _to_response(self, result: dict[str, Any]) -> ResponseMeta:
        """Convert fetch result to ResponseMeta."""
        resp_headers: dict[str, list[str]] = {}
        for k, v in result.get("headers", {}).items():
            resp_headers.setdefault(k, []).append(v)
        return ResponseMeta(
            status_code=result.get("status", 0),
            status_reason=result.get("statusText", ""),
            headers=resp_headers,
            content=result.get("body", "").encode("utf-8"),
            error=result.get("error", ""),
        )

    async def send_payload(self, target_url: str, payload_info: PayloadInfo) -> Response:
        """Send a payload via fetch() from the solved page."""
        request = payload_info.get_request(target_url, HTTPClientType.GO_HTTP_CLIENT)
        if not isinstance(request, GoHTTPRequest):
            msg = f"bad request type: {type(request).__name__}"
            raise TypeError(msg)

        headers = dict(self._headers)
        headers.update(request.headers)
        if payload_info.debug_header_value:
            headers[GTW_DEBUG_HEADER] = payload_info.debug_header_value

        content_body: str | None = None
        if request.content:
            if isinstance(request.content, bytes):
                content_body = request.content.decode("utf-8", errors="replace")
            else:
                content_body = request.content

        if self._use_navigation:
            result = await self._navigate_fetch(request.url, request.method, headers, content_body)
        else:
            result = await self._execute_fetch(request.url, request.method, headers, content_body)
        return self._to_response(result)

    async def send_request(self, req: Request) -> Response:
        """Send a prepared request."""
        if not isinstance(req, GoHTTPRequest):
            msg = f"bad request type: {type(req).__name__}"
            raise TypeError(msg)

        headers = dict(self._headers)
        headers.update(req.headers)
        if req.debug_header_value:
            headers[GTW_DEBUG_HEADER] = req.debug_header_value

        content_body: str | None = None
        if req.content:
            content_body = req.content.decode("utf-8", errors="replace") if isinstance(req.content, bytes) else req.content

        if self._use_navigation:
            result = await self._navigate_fetch(req.url, req.method, headers, content_body)
        else:
            result = await self._execute_fetch(req.url, req.method, headers, content_body)
        return self._to_response(result)

    async def close(self) -> None:
        """Close — noop if using SessionManager (it owns the browser)."""
        if not self._session_mgr:
            try:
                if self._browser:
                    await self._browser.close()
                    self._browser = None
            except Exception:
                pass
            try:
                if self._pw:
                    await self._pw.stop()
                    self._pw = None
            except Exception:
                pass
            self._page = None
            self._context = None
