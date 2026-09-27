"""Payload information and request generation."""

from __future__ import annotations

from dataclasses import dataclass

from gotestwaf.errors import PayloadError
from gotestwaf.payload.encoder.encoder import apply_encoder
from gotestwaf.payload.placeholder.placeholder import PlaceholderConfig, apply_placeholder
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest, Request


@dataclass(slots=True)
class PayloadInfo:
    """Holds information about a payload and its configuration."""

    payload: str = ""
    encoder_name: str = ""
    placeholder_name: str = ""
    placeholder_config: PlaceholderConfig | None = None
    debug_header_value: str = ""

    def get_encoded_payload(self) -> str:
        """Encode the payload using the specified encoder.

        Returns:
            The encoded payload string.

        Raises:
            PayloadError: If encoding fails.
        """
        try:
            return apply_encoder(self.encoder_name, self.payload)
        except Exception as e:
            msg = "couldn't encode payload"
            raise PayloadError(msg) from e

    def get_request(self, target_url: str, client_type: HTTPClientType) -> Request:
        """Generate a request based on payload info, target URL, and client type.

        Args:
            target_url: The target URL for the request.
            client_type: Which HTTP client type to use.

        Returns:
            A Request object ready to be sent.

        Raises:
            PayloadError: If request generation fails.
        """
        encoded_payload = self.get_encoded_payload()

        try:
            request = apply_placeholder(
                target_url,
                encoded_payload,
                self.placeholder_name,
                self.placeholder_config,
                client_type,
            )
        except Exception as e:
            msg = f"couldn't apply placeholder {self.placeholder_name}"
            raise PayloadError(msg) from e

        # Set debug header value on the request (matches Go's type switch for both clients)
        if isinstance(request, GoHTTPRequest):
            request.debug_header_value = self.debug_header_value
        else:
            from gotestwaf.scanner.types.request import ChromeDPTasks
            if isinstance(request, ChromeDPTasks):
                request.debug_header_value = self.debug_header_value

        return request
