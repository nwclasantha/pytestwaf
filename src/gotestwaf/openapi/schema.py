"""OpenAPI schema conversion to JSON/XML/form data structures."""

from __future__ import annotations

import json
import math
from typing import Any
from urllib.parse import quote, quote_plus
from xml.etree.ElementTree import Element, SubElement, tostring

from gotestwaf.openapi.helpers import (
    DEFAULT_STRING_SIZE,
    gen_random_float,
    gen_random_int,
    gen_random_placeholder,
    gen_random_string,
)

JSON_CONTENT_TYPE = "application/json"
XML_CONTENT_TYPE = "application/xml"
X_WWW_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
PLAIN_TEXT_CONTENT_TYPE = "text/plain"

XML_ATTRIBUTE_PREFIX = "-"
XML_HEADER = '<?xml version="1.0" encoding="UTF-8"?>'


class ParameterSpec:
    """Specification for a parameter with type and length constraints."""

    __slots__ = ("param_type", "value", "min_length", "max_length", "explode", "param_spec")

    def __init__(self) -> None:
        self.param_type: str = ""
        self.value: str = ""
        self.min_length: int = 0
        self.max_length: int = 2**63 - 1
        self.explode: bool = False
        self.param_spec: dict[str, ParameterSpec] = {}


def schema_to_map(
    name: str,
    schema: dict[str, Any],
    is_xml: bool,
) -> tuple[Any, bool, dict[str, ParameterSpec]]:
    """Convert an OpenAPI schema dict to a value structure.

    Args:
        name: Parameter name.
        schema: OpenAPI schema dictionary.
        is_xml: Whether to produce XML-compatible output.

    Returns:
        Tuple of (value, str_available, param_spec_dict).
    """
    # Handle allOf / anyOf
    all_of = schema.get("anyOf") or schema.get("allOf")
    if all_of:
        all_of_value: dict[str, Any] = {}
        all_of_param_spec: dict[str, ParameterSpec] = {}
        all_of_str_available = False

        for inner_schema in all_of:
            if inner_schema:
                inner_value, inner_str, inner_spec = schema_to_map(name, inner_schema, is_xml)
                if isinstance(inner_value, dict):
                    all_of_value.update(inner_value)
                all_of_param_spec.update(inner_spec)
                all_of_str_available = all_of_str_available or inner_str

        return all_of_value, all_of_str_available, all_of_param_spec

    # Handle oneOf
    one_of = schema.get("oneOf")
    if one_of:
        best_value: Any = None
        best_str_available = False
        best_param_spec: dict[str, ParameterSpec] = {}

        for inner_schema in one_of:
            if inner_schema:
                inner_value, inner_str, inner_spec = schema_to_map(name, inner_schema, is_xml)
                if inner_str and len(inner_spec) > len(best_param_spec):
                    best_value = inner_value
                    best_param_spec = inner_spec
                    best_str_available = inner_str

        return best_value, best_str_available, best_param_spec

    str_available = False
    param_spec: dict[str, ParameterSpec] = {}

    # XML name/attribute handling (mirrors Go lines 101-113)
    xml_data = schema.get("xml", {}) or {}
    if is_xml and xml_data:
        if xml_data.get("name"):
            name = xml_data["name"]
        if name:
            if xml_data.get("attribute"):
                name = XML_ATTRIBUTE_PREFIX + name
            elif xml_data.get("prefix"):
                name = xml_data["prefix"] + ":" + name

    # Get type
    schema_type = schema.get("type", "")
    if isinstance(schema_type, list):
        schema_type = schema_type[0] if schema_type else ""

    match schema_type:
        case "integer":
            rand_int = gen_random_int(
                schema.get("minimum"), schema.get("maximum"),
                schema.get("exclusiveMinimum", False), schema.get("exclusiveMaximum", False),
            )
            value: Any = str(rand_int)

        case "number":
            rand_float = gen_random_float(
                schema.get("minimum"), schema.get("maximum"),
                schema.get("exclusiveMinimum", False), schema.get("exclusiveMaximum", False),
            )
            value = f"{rand_float:f}"

        case "string":
            value = gen_random_placeholder()
            str_available = True
            spec = ParameterSpec()
            spec.param_type = schema_type
            spec.min_length = schema.get("minLength", 0)
            max_len = schema.get("maxLength")
            if max_len is None:
                spec.max_length = 2**63 - 1
                spec.value = gen_random_string(spec.min_length, spec.min_length + DEFAULT_STRING_SIZE)
            else:
                spec.max_length = max_len
                spec.value = gen_random_string(spec.min_length, spec.max_length)
            param_spec[value] = spec

        case "boolean":
            value = "false"

        case "array":
            items_schema = schema.get("items", {})
            inner, inner_str, inner_spec = schema_to_map(name, items_schema, is_xml)
            min_items = max(int(schema.get("minItems", 1)), 1)
            value = [inner] * min_items
            str_available = inner_str
            param_spec = inner_spec

        case "object":
            map_structure: dict[str, Any] = {}
            for prop_name, prop_schema in schema.get("properties", {}).items():
                inner, inner_str, inner_spec = schema_to_map(prop_name, prop_schema, is_xml)
                str_available = str_available or inner_str
                if is_xml and isinstance(inner, dict):
                    map_structure.update(inner)
                else:
                    map_structure[prop_name] = inner
                param_spec.update(inner_spec)
            value = map_structure

        case _:
            value = ""

    # XML post-processing: wrap value for mxj-compatible XML serialization
    # (mirrors Go lines 202-234)
    if is_xml:
        if isinstance(value, dict):
            wrapped_value = value
        else:
            wrapped_value = {"#text": value, "#seq": 0}

        # Add XML namespace attribute if specified
        if xml_data.get("namespace"):
            xmlns = "xmlns"
            if xml_data.get("prefix"):
                xmlns = f"xmlns:{xml_data['prefix']}"
            wrapped_value["#attr"] = {
                xmlns: {"#text": xml_data["namespace"], "#seq": 0},
            }

        value = wrapped_value

        if name:
            value = {name: value}

    return value, str_available, param_spec


def json_marshal(schema_structure: Any) -> str:
    """Dump structure as JSON string."""
    return json.dumps(schema_structure)


def xml_marshal(schema_structure: Any) -> str:
    """Dump structure as XML string."""
    if not isinstance(schema_structure, dict):
        msg = "input value must be dict"
        raise TypeError(msg)

    def _dict_to_xml(parent: Element, data: dict[str, Any]) -> None:
        for key, val in data.items():
            if isinstance(val, dict):
                child = SubElement(parent, key)
                _dict_to_xml(child, val)
            elif isinstance(val, list):
                for item in val:
                    child = SubElement(parent, key)
                    if isinstance(item, dict):
                        _dict_to_xml(child, item)
                    else:
                        child.text = str(item)
            else:
                child = SubElement(parent, key)
                child.text = str(val)

    root = Element("root")
    _dict_to_xml(root, schema_structure)
    return XML_HEADER + tostring(root, encoding="unicode")


def html_form_marshal(schema_structure: Any) -> str:
    """Dump structure as URL-encoded form data."""
    if not isinstance(schema_structure, dict):
        msg = "input value must be dict"
        raise TypeError(msg)

    parts: list[str] = []
    for k, v in schema_structure.items():
        if isinstance(v, str):
            parts.append(f"{quote_plus(k)}={quote_plus(v)}")
        else:
            json_val = json.dumps(v)
            parts.append(f"{quote_plus(k)}={quote_plus(json_val)}")

    return "&".join(parts)
