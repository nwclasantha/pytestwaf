"""gRPC client for sending payloads via gRPC protocol."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gotestwaf.helpers.url import host_port_from_url
from gotestwaf.scanner.types.response import Response, ResponseMeta

if TYPE_CHECKING:
    from gotestwaf.config.config import Config
    from gotestwaf.payload.payload import PayloadInfo

GRPC_SERVER_DETECTION_TIMEOUT = 3.0


class Client:
    """gRPC client for WAF testing."""

    def __init__(self, cfg: Config) -> None:
        self._is_available = True
        self._host = ""
        self._channel = None
        self._is_tls = False
        self._tls_verify = cfg.tls_verify

        if cfg.grpc_port == 0:
            self._is_available = False
            return

        is_tls, host = host_port_from_url(cfg.url, cfg.grpc_port)
        self._host = host
        self._is_tls = is_tls

    async def check_availability(self) -> bool:
        """Check if gRPC server is available.

        Returns:
            True if server is available.
        """
        if not self._is_available:
            return False

        try:
            import grpc

            if self._is_tls:
                credentials = grpc.ssl_channel_credentials()
                channel = grpc.aio.secure_channel(self._host, credentials)
            else:
                channel = grpc.aio.insecure_channel(self._host)

            # Try a simple health check
            try:
                from grpc_health.v1 import health_pb2, health_pb2_grpc

                stub = health_pb2_grpc.HealthStub(channel)
                await stub.Check(
                    health_pb2.HealthCheckRequest(service="ServiceFooBar"),
                    timeout=GRPC_SERVER_DETECTION_TIMEOUT,
                )
                self._is_available = True
            except grpc.RpcError:
                # gRPC error means server is responding with gRPC protocol
                self._is_available = True
            except Exception:
                self._is_available = False
            finally:
                await channel.close()

        except Exception:
            self._is_available = False

        return self._is_available

    def is_available(self) -> bool:
        """Return current availability status."""
        return self._is_available

    async def send_payload(self, payload_info: PayloadInfo, debug_header_value: str = "") -> Response:
        """Send a payload via gRPC with optional debug header as metadata.

        Args:
            payload_info: The payload to send.
            debug_header_value: If set, injected as X-GoTestWAF-Test gRPC metadata.

        Returns:
            Response with status code mapped from gRPC status.
        """
        if not self._is_available:
            return ResponseMeta(status_code=0)

        encoded_payload = payload_info.get_encoded_payload()

        try:
            import grpc

            if self._channel is None:
                if self._is_tls:
                    credentials = grpc.ssl_channel_credentials()
                    self._channel = grpc.aio.secure_channel(self._host, credentials)
                else:
                    self._channel = grpc.aio.insecure_channel(self._host)

            # Import generated protobuf stubs
            from gotestwaf.payload.placeholder.grpc import service_pb2, service_pb2_grpc

            stub = service_pb2_grpc.ServiceFooBarStub(self._channel)
            response = ResponseMeta(status_code=200)

            # Build metadata with debug header (mirrors Go's metadata.AppendToOutgoingContext)
            metadata: list[tuple[str, str]] = []
            if debug_header_value:
                from gotestwaf.scanner.clients import GTW_DEBUG_HEADER
                metadata.append((GTW_DEBUG_HEADER.lower(), debug_header_value))

            try:
                resp = await stub.foo(
                    service_pb2.Request(value=encoded_payload),
                    metadata=metadata if metadata else None,
                )
                response.content = resp.value.encode("utf-8")
            except grpc.RpcError as e:
                # Map gRPC status codes to HTTP status codes
                grpc_to_http = {
                    grpc.StatusCode.OK: 200,
                    grpc.StatusCode.CANCELLED: 499,
                    grpc.StatusCode.UNKNOWN: 500,
                    grpc.StatusCode.INVALID_ARGUMENT: 400,
                    grpc.StatusCode.DEADLINE_EXCEEDED: 504,
                    grpc.StatusCode.NOT_FOUND: 404,
                    grpc.StatusCode.ALREADY_EXISTS: 409,
                    grpc.StatusCode.PERMISSION_DENIED: 403,
                    grpc.StatusCode.RESOURCE_EXHAUSTED: 429,
                    grpc.StatusCode.FAILED_PRECONDITION: 400,
                    grpc.StatusCode.ABORTED: 409,
                    grpc.StatusCode.OUT_OF_RANGE: 400,
                    grpc.StatusCode.UNIMPLEMENTED: 501,
                    grpc.StatusCode.INTERNAL: 500,
                    grpc.StatusCode.UNAVAILABLE: 503,
                    grpc.StatusCode.DATA_LOSS: 500,
                    grpc.StatusCode.UNAUTHENTICATED: 401,
                }
                response.status_code = grpc_to_http.get(e.code(), 500)

            return response

        except Exception as exc:
            return ResponseMeta(status_code=500, error=str(exc))

    async def close(self) -> None:
        """Close the gRPC channel."""
        if self._channel is not None:
            await self._channel.close()
            self._channel = None
