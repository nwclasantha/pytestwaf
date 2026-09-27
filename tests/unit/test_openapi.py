"""Tests for OpenAPI module."""

from __future__ import annotations

import pytest

from gotestwaf.openapi.helpers import gen_random_int, gen_random_float, gen_random_string
from gotestwaf.openapi.schema import json_marshal, html_form_marshal, schema_to_map


class TestHelpers:
    def test_gen_random_int_within_bounds(self) -> None:
        result = gen_random_int(min_val=5.0, max_val=10.0)
        assert 5 <= result <= 10

    def test_gen_random_float_within_bounds(self) -> None:
        result = gen_random_float(min_val=1.0, max_val=100.0)
        assert 1.0 <= result <= 101.0

    def test_gen_random_string_min_length(self) -> None:
        result = gen_random_string(20, 30)
        assert 20 <= len(result) <= 30


class TestSchema:
    def test_schema_to_map_string(self) -> None:
        schema = {"type": "string"}
        value, str_available, param_spec = schema_to_map("test", schema, False)
        assert str_available is True
        assert isinstance(value, str)
        assert len(param_spec) == 1

    def test_schema_to_map_integer(self) -> None:
        schema = {"type": "integer", "minimum": 1, "maximum": 100}
        value, str_available, param_spec = schema_to_map("test", schema, False)
        assert str_available is False
        assert isinstance(value, str)

    def test_schema_to_map_object(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
            },
        }
        value, str_available, param_spec = schema_to_map("test", schema, False)
        assert isinstance(value, dict)
        assert "name" in value
        assert "age" in value

    def test_json_marshal(self) -> None:
        result = json_marshal({"key": "value"})
        assert '"key"' in result
        assert '"value"' in result

    def test_html_form_marshal(self) -> None:
        result = html_form_marshal({"name": "test", "value": "data"})
        assert "name=test" in result
        assert "value=data" in result
