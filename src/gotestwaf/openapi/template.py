"""HTTP request template generation from OpenAPI specifications."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from gotestwaf.openapi.parameters import AllParameters, parse_parameters
from gotestwaf.openapi.placeholders import (
    HEADER_PLACEHOLDER,
    HTML_FORM_PLACEHOLDER,
    JSON_BODY_PLACEHOLDER,
    JSON_REQUEST_PLACEHOLDER,
    REQUEST_BODY_PLACEHOLDER,
    URL_PARAM_PLACEHOLDER,
    URL_PATH_PLACEHOLDER,
    XML_BODY_PLACEHOLDER,
)
from gotestwaf.openapi.schema import (
    JSON_CONTENT_TYPE,
    PLAIN_TEXT_CONTENT_TYPE,
    X_WWW_FORM_CONTENT_TYPE,
    XML_CONTENT_TYPE,
    ParameterSpec,
    html_form_marshal,
    json_marshal,
    schema_to_map,
    xml_marshal,
)
from gotestwaf.scanner.types.request import GoHTTPRequest

# Templates maps placeholder name → list of Template
Templates = dict[str, list["Template"]]


@dataclass
class Template:
    """Contains all information about an OpenAPI request template."""

    method: str = ""
    path: str = ""
    url: str = ""
    path_parameters: dict[str, ParameterSpec] = field(default_factory=dict)
    query_parameters: dict[str, ParameterSpec] = field(default_factory=dict)
    headers: dict[str, ParameterSpec] = field(default_factory=dict)
    request_body_parameters: dict[str, ParameterSpec] = field(default_factory=dict)
    request_body: dict[str, str] = field(default_factory=dict)
    placeholders: dict[str, None] = field(default_factory=dict)

    def create_request(self, placeholder: str, payload: str) -> GoHTTPRequest | None:
        """Generate a request with the payload substituted as the placeholder value.

        Args:
            placeholder: Which placeholder to use for payload substitution.
            payload: The encoded payload string.

        Returns:
            GoHTTPRequest or None if placeholder not supported.
        """
        if placeholder not in self.placeholders:
            return None

        body = ""
        content_type = ""
        query_params: dict[str, str] = {}
        headers: dict[str, str] = {}
        path = self.url

        match placeholder:
            case p if p == HEADER_PLACEHOLDER:
                for header, spec in self.headers.items():
                    if spec.param_type == "string":
                        payload_len = len(payload)
                        if spec.min_length <= payload_len <= spec.max_length:
                            headers[header] = payload
                            continue
                    headers[header] = spec.value

            case p if p == URL_PATH_PLACEHOLDER:
                for param, spec in self.path_parameters.items():
                    if spec.param_type == "string":
                        payload_len = len(payload)
                        if spec.min_length <= payload_len <= spec.max_length:
                            path = path.replace(param, payload)
                            continue
                    path = path.replace(param, spec.value)

            case p if p == URL_PARAM_PLACEHOLDER:
                for param, spec in self.query_parameters.items():
                    if spec.param_type == "string":
                        payload_len = len(payload)
                        if spec.min_length <= payload_len <= spec.max_length:
                            query_params[param] = payload
                            continue
                    query_params[param] = spec.value

            case p if p == HTML_FORM_PLACEHOLDER:
                body = self.request_body.get(X_WWW_FORM_CONTENT_TYPE, "")
                content_type = X_WWW_FORM_CONTENT_TYPE
                for default_val, spec in self.request_body_parameters.items():
                    if spec.param_type == "string":
                        payload_len = len(payload)
                        if spec.min_length <= payload_len <= spec.max_length:
                            body = body.replace(default_val, payload)

            case p if p in (JSON_BODY_PLACEHOLDER, JSON_REQUEST_PLACEHOLDER):
                body = self.request_body.get(JSON_CONTENT_TYPE, "")
                content_type = JSON_CONTENT_TYPE
                for default_val, spec in self.request_body_parameters.items():
                    if spec.param_type == "string":
                        payload_len = len(payload)
                        if spec.min_length <= payload_len <= spec.max_length:
                            body = body.replace(default_val, payload)

            case p if p == XML_BODY_PLACEHOLDER:
                body = self.request_body.get(XML_CONTENT_TYPE, "")
                content_type = XML_CONTENT_TYPE
                for default_val, spec in self.request_body_parameters.items():
                    if spec.param_type == "string":
                        payload_len = len(payload)
                        if spec.min_length <= payload_len <= spec.max_length:
                            body = body.replace(default_val, payload)

            case p if p == REQUEST_BODY_PLACEHOLDER:
                body = self.request_body.get(PLAIN_TEXT_CONTENT_TYPE, "")
                content_type = PLAIN_TEXT_CONTENT_TYPE
                for default_val, spec in self.request_body_parameters.items():
                    if spec.param_type == "string":
                        payload_len = len(payload)
                        if spec.min_length <= payload_len <= spec.max_length:
                            body = body.replace(default_val, payload)

            case _:
                return None

        # Fill remaining path parameters
        if placeholder != URL_PATH_PLACEHOLDER:
            for k, v in self.path_parameters.items():
                path = path.replace(k, v.value)

        # Build query string (URL-encode values to prevent injection)
        if query_params:
            from urllib.parse import quote as _url_quote
            query_str = "&".join(f"{_url_quote(str(k), safe='')}={_url_quote(str(v), safe='')}" for k, v in query_params.items())
            if "?" in path:
                path += "&" + query_str
            else:
                path += "?" + query_str

        req_headers = dict(headers)
        if content_type:
            req_headers["Content-Type"] = content_type

        return GoHTTPRequest(
            method=self.method,
            url=path,
            headers=req_headers,
            content=body if body else None,
        )


def new_templates(openapi_doc: dict[str, Any], base_path: str) -> Templates:
    """Parse OpenAPI document and return all possible templates.

    Args:
        openapi_doc: Parsed OpenAPI specification dict.
        base_path: Base URL path for all endpoints.

    Returns:
        Dict mapping placeholder names to lists of Templates.
    """
    unsorted_templates: list[Template] = []
    paths = openapi_doc.get("paths", {})

    for path, path_info in paths.items():
        if not isinstance(path_info, dict):
            continue
        path_templates = _path_templates(openapi_doc, base_path, path, path_info)
        unsorted_templates.extend(path_templates)

    templates: Templates = {}
    for template in unsorted_templates:
        for placeholder in template.placeholders:
            templates.setdefault(placeholder, []).append(template)

    return templates


HTTP_METHODS = ["connect", "delete", "get", "head", "options", "patch", "post", "put", "trace"]


def _path_templates(
    openapi_doc: dict[str, Any],
    base_path: str,
    path: str,
    path_info: dict[str, Any],
) -> list[Template]:
    """Parse every HTTP method for a path."""
    templates: list[Template] = []

    for method in HTTP_METHODS:
        operation = path_info.get(method)
        if operation is not None:
            template = _operation_template(openapi_doc, base_path, path, method.upper(), operation)
            if template is not None:
                templates.append(template)

    return templates


def _operation_template(
    openapi_doc: dict[str, Any],
    base_path: str,
    path: str,
    method: str,
    operation: dict[str, Any],
) -> Template | None:
    """Parse a single operation into a Template."""
    template = Template(
        method=method,
        path=path,
    )

    # Parse parameters
    raw_params = operation.get("parameters", [])
    params = parse_parameters(raw_params)

    template.path_parameters = params.path_parameters
    template.query_parameters = params.query_parameters
    template.headers = params.headers
    template.url = base_path.rstrip("/") + path
    template.placeholders = dict(params.supported_placeholders)

    # Parse request body
    request_body_def = operation.get("requestBody")
    if request_body_def and isinstance(request_body_def, dict):
        # Coalesce explicit YAML `null` to {} so .items() never crashes.
        content = request_body_def.get("content") or {}
        if "value" in request_body_def and isinstance(request_body_def["value"], dict):
            content = request_body_def["value"].get("content") or {}

        for content_type, media_type in content.items():
            if not isinstance(media_type, dict):
                continue
            schema = media_type.get("schema") or {}
            if isinstance(schema, dict) and "value" in schema:
                schema = schema["value"] or {}

            raw_body, str_available, param_spec = schema_to_map("", schema, is_xml=(content_type == XML_CONTENT_TYPE))

            match content_type:
                case c if c == JSON_CONTENT_TYPE:
                    if str_available:
                        template.placeholders[JSON_REQUEST_PLACEHOLDER] = None
                        template.placeholders[JSON_BODY_PLACEHOLDER] = None
                    template.request_body[content_type] = json_marshal(raw_body)

                case c if c == XML_CONTENT_TYPE:
                    raw_body_xml, str_available_xml, param_spec_xml = schema_to_map("", schema, is_xml=True)
                    if str_available_xml:
                        template.placeholders[XML_BODY_PLACEHOLDER] = None
                    template.request_body[content_type] = xml_marshal(raw_body_xml)
                    param_spec = param_spec_xml

                case c if c == X_WWW_FORM_CONTENT_TYPE:
                    if str_available:
                        template.placeholders[HTML_FORM_PLACEHOLDER] = None
                    template.request_body[content_type] = html_form_marshal(raw_body)

                case _:
                    if str_available:
                        template.placeholders[REQUEST_BODY_PLACEHOLDER] = None
                    if isinstance(raw_body, dict):
                        for k, v in raw_body.items():
                            template.request_body[PLAIN_TEXT_CONTENT_TYPE] = str(v) if v is not None else k
                            break

            template.request_body_parameters.update(param_spec)

    return template
