"""Authentication support — login before scanning protected endpoints.

Supports:
- Static auth header: --authHeader "Authorization: Bearer xxx"
- Static cookies: --cookie "session=abc; token=xyz"
- Form-based login: --loginURL + --loginBody (auto-extracts Set-Cookie)
"""

from __future__ import annotations

import structlog

logger = structlog.get_logger()


def parse_auth_header(header_str: str) -> tuple[str, str]:
    """Parse 'Authorization: Bearer xxx' into (name, value)."""
    if ":" not in header_str:
        return "Authorization", header_str
    name, _, value = header_str.partition(":")
    return name.strip(), value.strip()


def parse_cookies(cookie_str: str) -> dict[str, str]:
    """Parse 'session=abc; token=xyz' into dict."""
    cookies: dict[str, str] = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            cookies[name.strip()] = value.strip()
    return cookies


async def perform_login(login_url: str, login_body: str, tls_verify: bool = False) -> dict[str, str]:
    """POST to login URL with body, extract cookies from response.

    Args:
        login_url: URL to POST to (e.g., https://target.com/api/login)
        login_body: JSON or form body (e.g., '{"user":"admin","pass":"test"}')
        tls_verify: Whether to verify TLS certificate

    Returns:
        Dict of cookie name -> value from Set-Cookie headers.
    """
    import httpx

    cookies: dict[str, str] = {}
    headers = {"Content-Type": "application/json"}

    # Detect if body is form-encoded or JSON
    if login_body.startswith("{"):
        headers["Content-Type"] = "application/json"
    elif "=" in login_body:
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    try:
        async with httpx.AsyncClient(verify=tls_verify, follow_redirects=True, timeout=30.0) as client:
            resp = await client.post(login_url, content=login_body.encode(), headers=headers)

            # Extract cookies from response
            for name, value in resp.cookies.items():
                cookies[name] = value

            # Also check Set-Cookie headers directly
            for cookie_header in resp.headers.get_list("set-cookie"):
                if "=" in cookie_header:
                    cookie_part = cookie_header.split(";")[0]
                    name, _, value = cookie_part.partition("=")
                    cookies[name.strip()] = value.strip()

            if resp.status_code >= 400:
                logger.error("Login failed with error status", url=login_url, status=resp.status_code)
                raise RuntimeError(
                    f"Login to {login_url} returned HTTP {resp.status_code}. "
                    f"Aborting scan — running without auth would produce invalid results."
                )
            if cookies:
                logger.info("Login successful", url=login_url, status=resp.status_code, cookies=len(cookies))
            else:
                logger.error("Login returned no cookies", url=login_url, status=resp.status_code)
                raise RuntimeError(
                    f"Login to {login_url} returned HTTP {resp.status_code} but no cookies. "
                    f"Aborting scan — running without auth would produce invalid results."
                )

    except RuntimeError:
        raise
    except Exception as e:
        logger.error("Login failed", url=login_url, error=str(e))
        raise RuntimeError(f"Login to {login_url} failed: {e}") from e

    return cookies


def apply_auth_to_config(
    cfg: object,
    auth_header: str = "",
    auth_cookie: str = "",
    login_cookies: dict[str, str] | None = None,
) -> None:
    """Inject authentication into config headers so all requests include it.

    Args:
        cfg: Config object (has http_headers dict and add_header str)
        auth_header: Static auth header string
        auth_cookie: Static cookie string
        login_cookies: Cookies from form-based login
    """
    if auth_header:
        name, value = parse_auth_header(auth_header)
        cfg.http_headers[name] = value
        logger.info("Auth header added", header=name)

    # Build cookie header from all sources
    all_cookies: dict[str, str] = {}
    if auth_cookie:
        all_cookies.update(parse_cookies(auth_cookie))
    if login_cookies:
        all_cookies.update(login_cookies)

    if all_cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in all_cookies.items())
        cfg.http_headers["Cookie"] = cookie_str
        logger.info("Auth cookies added", count=len(all_cookies))
