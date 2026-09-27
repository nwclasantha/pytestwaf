"""OpenAPI parameter parsing for path, query, and header parameters."""

from __future__ import annotations

import math
from typing import Any
from urllib.parse import quote

from gotestwaf.openapi.helpers import (
    DEFAULT_STRING_SIZE,
    gen_random_float,
    gen_random_int,
    gen_random_string,
)
from gotestwaf.openapi.placeholders import (
    HEADER_PLACEHOLDER,
    URL_PARAM_PLACEHOLDER,
    URL_PATH_PLACEHOLDER,
)
from gotestwaf.openapi.schema import ParameterSpec, json_marshal, schema_to_map

DEFAULT_QUERY_ARRAY_BINDER = ","
SPACE_QUERY_ARRAY_BINDER = "%20"
PIPE_QUERY_ARRAY_BINDER = "|"


class AllParameters:
    """Contains parsed parameter names and their specifications."""

    __slots__ = ("path_parameters", "query_parameters", "headers", "supported_placeholders")

    def __init__(self) -> None:
        self.path_parameters: dict[str, ParameterSpec] = {}
        self.query_parameters: dict[str, ParameterSpec] = {}
        self.headers: dict[str, ParameterSpec] = {}
        self.supported_placeholders: dict[str, None] = {}


def parse_parameters(parameters: list[dict[str, Any]] | None) -> AllParameters:
    """Parse OpenAPI parameters into AllParameters.

    Args:
        parameters: List of OpenAPI parameter dicts.

    Returns:
        Parsed AllParameters object.
    """
    result = AllParameters()

    if not parameters:
        return result

    for p in parameters:
        param_in = p.get("in", "")
        match param_in:
            case "path":
                name, spec = _parse_path_parameter(p)
                result.path_parameters[name] = spec
                if spec.param_type == "string":
                    result.supported_placeholders[URL_PATH_PLACEHOLDER] = None

            case "query":
                name, spec = _parse_query_parameter(p)
                result.query_parameters[name] = spec
                if spec.param_type == "string":
                    result.supported_placeholders[URL_PARAM_PLACEHOLDER] = None

            case "header":
                name, spec = _parse_header_parameter(p)
                result.headers[name] = spec
                if spec.param_type == "string":
                    result.supported_placeholders[HEADER_PLACEHOLDER] = None

    return result


def _parse_path_parameter(parameter: dict[str, Any]) -> tuple[str, ParameterSpec]:
    """Parse a path parameter."""
    param_name = "{" + parameter.get("name", "") + "}"
    spec = ParameterSpec()
    schema = parameter.get("schema", {})

    param_type = schema.get("type", "")
    if isinstance(param_type, list):
        param_type = param_type[0] if param_type else ""

    spec.param_type = param_type

    match param_type:
        case "number":
            rand_float = gen_random_float(schema.get("minimum"), schema.get("maximum"),
                                           schema.get("exclusiveMinimum", False), schema.get("exclusiveMaximum", False))
            spec.value = f"{rand_float:f}"
        case "integer":
            rand_int = gen_random_int(schema.get("minimum"), schema.get("maximum"),
                                      schema.get("exclusiveMinimum", False), schema.get("exclusiveMaximum", False))
            spec.value = str(rand_int)
        case "string":
            spec.min_length = schema.get("minLength", 0)
            max_len = schema.get("maxLength")
            spec.max_length = max_len if max_len is not None else 2**63 - 1
            spec.value = gen_random_string(spec.min_length, spec.min_length + DEFAULT_STRING_SIZE)

    return param_name, spec


def _parse_query_parameter(parameter: dict[str, Any]) -> tuple[str, ParameterSpec]:
    """Parse a query parameter."""
    param_name = parameter.get("name", "")
    spec = ParameterSpec()
    schema = parameter.get("schema", {})

    param_type = schema.get("type", "")
    if isinstance(param_type, list):
        param_type = param_type[0] if param_type else ""

    spec.param_type = param_type

    match param_type:
        case "number":
            rand_float = gen_random_float(schema.get("minimum"), schema.get("maximum"),
                                           schema.get("exclusiveMinimum", False), schema.get("exclusiveMaximum", False))
            spec.value = f"{rand_float:f}"
        case "integer":
            rand_int = gen_random_int(schema.get("minimum"), schema.get("maximum"),
                                      schema.get("exclusiveMinimum", False), schema.get("exclusiveMaximum", False))
            spec.value = str(rand_int)
        case "string":
            spec.min_length = schema.get("minLength", 0)
            max_len = schema.get("maxLength")
            spec.max_length = max_len if max_len is not None else 2**63 - 1
            spec.value = gen_random_string(spec.min_length, spec.min_length + DEFAULT_STRING_SIZE)
        case "boolean":
            spec.value = "false"
        case "array":
            items = schema.get("items", {})
            item_type = items.get("type", "")
            if isinstance(item_type, list):
                item_type = item_type[0] if item_type else ""
            spec.param_type = item_type
            match item_type:
                case "number":
                    rand_float = gen_random_float(items.get("minimum"), items.get("maximum"),
                                                   items.get("exclusiveMinimum", False), items.get("exclusiveMaximum", False))
                    spec.value = f"{rand_float:f}"
                case "integer":
                    rand_int = gen_random_int(items.get("minimum"), items.get("maximum"),
                                              items.get("exclusiveMinimum", False), items.get("exclusiveMaximum", False))
                    spec.value = str(rand_int)
                case "string":
                    spec.min_length = items.get("minLength", 0)
                    max_len = items.get("maxLength")
                    spec.max_length = max_len if max_len is not None else 2**63 - 1
                    spec.value = gen_random_string(spec.min_length, spec.min_length + DEFAULT_STRING_SIZE)

    return param_name, spec


def _parse_header_parameter(parameter: dict[str, Any]) -> tuple[str, ParameterSpec]:
    """Parse a header parameter."""
    param_name = parameter.get("name", "")
    spec = ParameterSpec()
    schema = parameter.get("schema", {})

    param_type = schema.get("type", "")
    if isinstance(param_type, list):
        param_type = param_type[0] if param_type else ""

    spec.param_type = param_type

    match param_type:
        case "number":
            rand_float = gen_random_float(schema.get("minimum"), schema.get("maximum"),
                                           schema.get("exclusiveMinimum", False), schema.get("exclusiveMaximum", False))
            spec.value = f"{rand_float:f}"
        case "integer":
            rand_int = gen_random_int(schema.get("minimum"), schema.get("maximum"),
                                      schema.get("exclusiveMinimum", False), schema.get("exclusiveMaximum", False))
            spec.value = str(rand_int)
        case "string":
            spec.min_length = schema.get("minLength", 0)
            max_len = schema.get("maxLength")
            spec.max_length = max_len if max_len is not None else 2**63 - 1
            spec.value = gen_random_string(spec.min_length, spec.min_length + DEFAULT_STRING_SIZE)

    return param_name, spec
