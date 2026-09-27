"""Email report sending to the GoTestWAF report server."""

from __future__ import annotations

from typing import Any

import httpx
import orjson

import os

DEFAULT_SERVER_URL = "https://gotestwaf.wallarm.tools/v1/send-report"


class EmailErrorResponse(Exception):
    """Error response from the email server."""

    def __init__(self, msg: str) -> None:
        self.msg = msg
        super().__init__(msg)


async def send_email(
    report_data: dict[str, Any],
    email: str,
    server_url: str | None = None,
) -> None:
    """Send report data to the GoTestWAF report server for email delivery.

    Args:
        report_data: Report data dictionary to send.
        email: Recipient email address.
        server_url: Override email server URL. Defaults to env var
            GTW_EMAIL_SERVER_URL or the built-in Wallarm endpoint.

    Raises:
        EmailErrorResponse: If the server returns an error.
        RuntimeError: If the request fails.
    """
    url = server_url or os.environ.get("GTW_EMAIL_SERVER_URL", DEFAULT_SERVER_URL)

    async with httpx.AsyncClient(timeout=60.0) as client:
        data = orjson.dumps(report_data)

        resp = await client.post(
            url,
            content=data,
            params={"email": email},
            headers={"Content-Type": "application/json"},
        )

        match resp.status_code:
            case 200:
                return
            case 400 | 413 | 429 | 500:
                try:
                    err_body = orjson.loads(resp.content)
                    msg = err_body.get("msg", "unknown error")
                except Exception:
                    msg = resp.text
                raise EmailErrorResponse(msg)
            case _:
                msg = f"bad status code: {resp.status_code}"
                raise RuntimeError(msg)
