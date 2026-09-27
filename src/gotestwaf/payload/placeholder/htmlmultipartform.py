"""HTMLMultipartForm placeholder - places payload as multipart form data."""

from __future__ import annotations

import io
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from typing import Any

from gotestwaf.payload.placeholder.placeholder import PlaceholderConfig
from gotestwaf.payload.placeholder.utils import random_hex
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest, Request

SEED = 5


@dataclass(slots=True)
class HTMLMultipartFormPlaceholder:
    """Places payload as multipart form data in a POST request."""

    name: str = "HTMLMultipartForm"

    def new_placeholder_config(self, conf: dict[Any, Any]) -> PlaceholderConfig | None:
        return None

    def get_name(self) -> str:
        return self.name

    def create_request(
        self,
        request_url: str,
        payload: str,
        config: PlaceholderConfig | None,
        http_client_type: HTTPClientType,
    ) -> Request:
        random_name = random_hex(SEED)
        boundary = random_hex(16)

        body = io.BytesIO()
        body.write(f"--{boundary}\r\n".encode())
        body.write(f'Content-Disposition: form-data; name="{random_name}"\r\n'.encode())
        body.write(b"\r\n")
        body.write(payload.encode("utf-8"))
        body.write(f"\r\n--{boundary}--\r\n".encode())

        content_type = f"multipart/form-data; boundary={boundary}"

        return GoHTTPRequest(
            method="POST",
            url=request_url,
            headers={"Content-Type": content_type},
            content=body.getvalue(),
        )


default_html_multipart_form = HTMLMultipartFormPlaceholder()
