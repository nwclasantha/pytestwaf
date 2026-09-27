"""Tests for OpenAPI module — loader, parameters, schema, template."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from gotestwaf.openapi.helpers import gen_random_float, gen_random_int, gen_random_placeholder, gen_random_string
from gotestwaf.openapi.loader import load_openapi_spec
from gotestwaf.openapi.parameters import AllParameters, parse_parameters
from gotestwaf.openapi.placeholders import (
    HEADER_PLACEHOLDER,
    HTML_FORM_PLACEHOLDER,
    JSON_BODY_PLACEHOLDER,
    URL_PARAM_PLACEHOLDER,
    URL_PATH_PLACEHOLDER,
)
from gotestwaf.openapi.schema import (
    ParameterSpec,
    html_form_marshal,
    json_marshal,
    schema_to_map,
    xml_marshal,
)
from gotestwaf.openapi.template import Template, new_templates


class TestLoader:
    def test_load_existing_file(self, tmp_path: Path) -> None:
        spec = tmp_path / "api.yaml"
        spec.write_text("openapi: '3.0.0'\ninfo:\n  title: Test\n  version: '1.0'\npaths: {}\n")
        result = load_openapi_spec(str(spec))
        assert result["openapi"] == "3.0.0"

    def test_load_missing_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_openapi_spec("/nonexistent/api.yaml")

    def test_load_empty_file(self, tmp_path: Path) -> None:
        spec = tmp_path / "empty.yaml"
        spec.write_text("")
        with pytest.raises(ValueError, match="empty"):
            load_openapi_spec(str(spec))


class TestParameters:
    def test_parse_none(self) -> None:
        result = parse_parameters(None)
        assert isinstance(result, AllParameters)
        assert len(result.path_parameters) == 0

    def test_parse_empty(self) -> None:
        result = parse_parameters([])
        assert len(result.query_parameters) == 0

    def test_parse_path_string_param(self) -> None:
        params = [{"name": "id", "in": "path", "schema": {"type": "string"}}]
        result = parse_parameters(params)
        assert "{id}" in result.path_parameters
        assert result.path_parameters["{id}"].param_type == "string"
        assert URL_PATH_PLACEHOLDER in result.supported_placeholders

    def test_parse_query_integer_param(self) -> None:
        params = [{"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 100}}]
        result = parse_parameters(params)
        assert "page" in result.query_parameters
        assert result.query_parameters["page"].param_type == "integer"

    def test_parse_header_param(self) -> None:
        params = [{"name": "X-API-Key", "in": "header", "schema": {"type": "string"}}]
        result = parse_parameters(params)
        assert "X-API-Key" in result.headers
        assert HEADER_PLACEHOLDER in result.supported_placeholders


class TestSchema:
    def test_string_type(self) -> None:
        value, str_avail, spec = schema_to_map("test", {"type": "string"}, False)
        assert str_avail is True
        assert isinstance(value, str)
        assert len(spec) == 1

    def test_integer_type(self) -> None:
        value, str_avail, spec = schema_to_map("test", {"type": "integer", "minimum": 1, "maximum": 100}, False)
        assert str_avail is False
        assert isinstance(value, str)  # Integer as string

    def test_boolean_type(self) -> None:
        value, str_avail, spec = schema_to_map("test", {"type": "boolean"}, False)
        assert value == "false"
        assert str_avail is False

    def test_array_type(self) -> None:
        value, str_avail, spec = schema_to_map("test", {"type": "array", "items": {"type": "string"}}, False)
        assert isinstance(value, list)
        assert len(value) >= 1

    def test_object_type(self) -> None:
        value, str_avail, spec = schema_to_map("test", {
            "type": "object",
            "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
        }, False)
        assert isinstance(value, dict)
        assert "name" in value
        assert "age" in value

    def test_xml_wrapping(self) -> None:
        value, _, _ = schema_to_map("item", {"type": "string"}, True)
        assert isinstance(value, dict)
        assert "item" in value or "#text" in str(value)

    def test_json_marshal(self) -> None:
        result = json_marshal({"key": "value"})
        assert '"key"' in result

    def test_html_form_marshal(self) -> None:
        result = html_form_marshal({"name": "test", "value": "data"})
        assert "name=test" in result
        assert "value=data" in result

    def test_html_form_marshal_complex_value(self) -> None:
        result = html_form_marshal({"data": [1, 2, 3]})
        assert "data=" in result
        # Complex values should be JSON-encoded and query-escaped
        assert "%5B" in result or "[" in result

    def test_xml_marshal(self) -> None:
        result = xml_marshal({"root": {"child": "value"}})
        assert "<?xml" in result
        assert "child" in result


class TestTemplate:
    def test_new_templates_empty(self) -> None:
        result = new_templates({"paths": {}}, "http://test.com")
        assert isinstance(result, dict)
        assert len(result) == 0

    def test_new_templates_with_get(self) -> None:
        doc = {
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {"name": "q", "in": "query", "schema": {"type": "string"}},
                        ],
                    },
                },
            },
        }
        result = new_templates(doc, "http://test.com")
        assert URL_PARAM_PLACEHOLDER in result
        assert len(result[URL_PARAM_PLACEHOLDER]) > 0

    def test_template_create_request(self) -> None:
        tmpl = Template(
            method="GET",
            path="/users",
            url="http://test.com/users",
            query_parameters={"q": ParameterSpec()},
            placeholders={URL_PARAM_PLACEHOLDER: None},
        )
        tmpl.query_parameters["q"].param_type = "string"
        tmpl.query_parameters["q"].value = "default"
        tmpl.query_parameters["q"].min_length = 0
        tmpl.query_parameters["q"].max_length = 2**63 - 1

        req = tmpl.create_request(URL_PARAM_PLACEHOLDER, "injected")
        assert req is not None
        assert "injected" in req.url

    def test_template_unsupported_placeholder(self) -> None:
        tmpl = Template(method="GET", path="/", url="http://test.com/", placeholders={})
        req = tmpl.create_request("NonExistent", "payload")
        assert req is None
