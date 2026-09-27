"""Placeholder interface and registry for request payload placement."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from gotestwaf.errors import BadPlaceholderConfigError, UnknownPlaceholderError
from gotestwaf.helpers.hash import HashProtocol
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import Request

SEED = 5
PAYLOAD_PLACEHOLDER = "{{payload}}"


class PlaceholderConfig(HashProtocol, Protocol):
    """Protocol for placeholder configuration objects."""

    ...


@runtime_checkable
class Placeholder(Protocol):
    """Protocol for payload placeholders."""

    def new_placeholder_config(self, conf: dict[Any, Any]) -> PlaceholderConfig | None: ...
    def get_name(self) -> str: ...
    def create_request(
        self,
        request_url: str,
        payload: str,
        config: PlaceholderConfig | None,
        http_client_type: HTTPClientType,
    ) -> Request: ...


# Registry populated lazily
_placeholders: dict[str, Placeholder] = {}


def _init_placeholders() -> None:
    """Initialize the placeholder registry."""
    from gotestwaf.payload.placeholder.graphql import default_graphql
    from gotestwaf.payload.placeholder.grpc_placeholder import default_grpc
    from gotestwaf.payload.placeholder.header import default_header
    from gotestwaf.payload.placeholder.htmlform import default_html_form
    from gotestwaf.payload.placeholder.htmlmultipartform import default_html_multipart_form
    from gotestwaf.payload.placeholder.jsonbody import default_json_body
    from gotestwaf.payload.placeholder.jsonrequest import default_json_request
    from gotestwaf.payload.placeholder.rawrequest import default_raw_request
    from gotestwaf.payload.placeholder.requestbody import default_request_body
    from gotestwaf.payload.placeholder.soapbody import default_soap_body
    from gotestwaf.payload.placeholder.urlparam import default_url_param
    from gotestwaf.payload.placeholder.urlpath import default_url_path
    from gotestwaf.payload.placeholder.useragent import default_user_agent
    from gotestwaf.payload.placeholder.xmlbody import default_xml_body

    all_placeholders: list[Placeholder] = [
        default_graphql,
        default_grpc,
        default_header,
        default_html_form,
        default_html_multipart_form,
        default_json_body,
        default_json_request,
        default_raw_request,
        default_request_body,
        default_soap_body,
        default_url_param,
        default_url_path,
        default_user_agent,
        default_xml_body,
    ]

    for ph in all_placeholders:
        _placeholders[ph.get_name()] = ph


def get_placeholders() -> dict[str, Placeholder]:
    """Return the placeholder registry, initializing if needed."""
    if not _placeholders:
        _init_placeholders()
    return _placeholders


def get_placeholder_config(name: str, conf: Any) -> PlaceholderConfig | None:
    """Parse placeholder configuration from raw config data.

    Args:
        name: The placeholder name.
        conf: Raw configuration data (typically a dict).

    Returns:
        Parsed PlaceholderConfig or None.

    Raises:
        UnknownPlaceholderError: If the placeholder is not found.
        BadPlaceholderConfigError: If the config is invalid.
    """
    placeholders = get_placeholders()
    ph = placeholders.get(name)
    if ph is None:
        raise UnknownPlaceholderError(name)

    if not isinstance(conf, dict):
        raise BadPlaceholderConfigError(
            name, f"bad placeholder config, expected: dict, got: {type(conf).__name__}"
        )

    return ph.new_placeholder_config(conf)


def apply_placeholder(
    url: str,
    data: str,
    placeholder_name: str,
    config: PlaceholderConfig | None,
    http_client_type: HTTPClientType,
) -> Request:
    """Apply a placeholder by name to create a request.

    Args:
        url: Target URL.
        data: Encoded payload data.
        placeholder_name: Name of the placeholder.
        config: Optional placeholder configuration.
        http_client_type: Which HTTP client type to generate the request for.

    Returns:
        A Request object.

    Raises:
        UnknownPlaceholderError: If the placeholder is not found.
    """
    placeholders = get_placeholders()
    ph = placeholders.get(placeholder_name)
    if ph is None:
        raise UnknownPlaceholderError(placeholder_name)

    return ph.create_request(url, data, config, http_client_type)
