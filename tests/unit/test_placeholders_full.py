"""Comprehensive tests for all placeholder implementations."""

from __future__ import annotations

import pytest

from gotestwaf.payload.placeholder.graphql import GraphQLConfig, GraphQLPlaceholder
from gotestwaf.payload.placeholder.grpc_placeholder import GRPCPlaceholder
from gotestwaf.payload.placeholder.header import HeaderPlaceholder
from gotestwaf.payload.placeholder.htmlform import HTMLFormPlaceholder
from gotestwaf.payload.placeholder.htmlmultipartform import HTMLMultipartFormPlaceholder
from gotestwaf.payload.placeholder.jsonbody import JSONBodyPlaceholder
from gotestwaf.payload.placeholder.jsonrequest import JSONRequestPlaceholder
from gotestwaf.payload.placeholder.rawrequest import RawRequestConfig, RawRequestPlaceholder
from gotestwaf.payload.placeholder.requestbody import RequestBodyPlaceholder
from gotestwaf.payload.placeholder.soapbody import SOAPBodyPlaceholder
from gotestwaf.payload.placeholder.urlparam import URLParamPlaceholder
from gotestwaf.payload.placeholder.urlpath import URLPathPlaceholder
from gotestwaf.payload.placeholder.useragent import UserAgentPlaceholder
from gotestwaf.payload.placeholder.xmlbody import XMLBodyPlaceholder
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest


URL = "http://example.com"
PAYLOAD = "test-payload"
CLIENT = HTTPClientType.GO_HTTP_CLIENT


class TestJSONBody:
    def test_creates_post_with_json_content_type(self) -> None:
        ph = JSONBodyPlaceholder()
        req = ph.create_request(URL, PAYLOAD, None, CLIENT)
        assert isinstance(req, GoHTTPRequest)
        assert req.method == "POST"
        assert req.headers.get("Content-Type") == "application/json"
        assert req.content == PAYLOAD

    def test_name(self) -> None:
        assert JSONBodyPlaceholder().get_name() == "JSONBody"


class TestJSONRequest:
    def test_wraps_payload_in_json_object(self) -> None:
        ph = JSONRequestPlaceholder()
        req = ph.create_request(URL, PAYLOAD, None, CLIENT)
        assert isinstance(req, GoHTTPRequest)
        assert req.method == "POST"
        assert '"test": true' in str(req.content)
        assert req.headers.get("Content-Type") == "application/json"


class TestHTMLForm:
    def test_creates_form_encoded_body(self) -> None:
        ph = HTMLFormPlaceholder()
        req = ph.create_request(URL, PAYLOAD, None, CLIENT)
        assert isinstance(req, GoHTTPRequest)
        assert req.method == "POST"
        assert req.headers.get("Content-Type") == "application/x-www-form-urlencoded"
        assert PAYLOAD in str(req.content)
        assert "=" in str(req.content)


class TestHTMLMultipartForm:
    def test_creates_multipart_body(self) -> None:
        ph = HTMLMultipartFormPlaceholder()
        req = ph.create_request(URL, PAYLOAD, None, CLIENT)
        assert isinstance(req, GoHTTPRequest)
        assert req.method == "POST"
        assert "multipart/form-data" in req.headers.get("Content-Type", "")
        assert "boundary" in req.headers.get("Content-Type", "")
        content = req.content if isinstance(req.content, bytes) else req.content.encode() if req.content else b""
        assert PAYLOAD.encode() in content


class TestRequestBody:
    def test_raw_body(self) -> None:
        ph = RequestBodyPlaceholder()
        req = ph.create_request(URL, PAYLOAD, None, CLIENT)
        assert isinstance(req, GoHTTPRequest)
        assert req.method == "POST"
        assert req.content == PAYLOAD


class TestSOAPBody:
    def test_creates_soap_envelope(self) -> None:
        ph = SOAPBodyPlaceholder()
        req = ph.create_request(URL, PAYLOAD, None, CLIENT)
        assert isinstance(req, GoHTTPRequest)
        assert req.method == "POST"
        assert req.headers.get("Content-Type") == "text/xml"
        assert "SOAPAction" in req.headers
        content = str(req.content)
        assert "soapenv:Envelope" in content
        assert "soapenv:Body" in content

    def test_soap_uses_tabs(self) -> None:
        """Verify SOAP template uses tab indentation matching Go."""
        ph = SOAPBodyPlaceholder()
        req = ph.create_request(URL, PAYLOAD, None, CLIENT)
        content = str(req.content)
        assert "\t<soapenv:Header>" in content


class TestXMLBody:
    def test_creates_xml_body(self) -> None:
        ph = XMLBodyPlaceholder()
        req = ph.create_request(URL, PAYLOAD, None, CLIENT)
        assert isinstance(req, GoHTTPRequest)
        assert req.method == "POST"
        assert req.headers.get("Content-Type") == "application/xml"
        assert req.content == PAYLOAD


class TestGraphQL:
    def test_get_method(self) -> None:
        ph = GraphQLPlaceholder()
        config = GraphQLConfig(method="GET")
        req = ph.create_request(URL, "{ users { id } }", config, CLIENT)
        assert isinstance(req, GoHTTPRequest)
        assert req.method == "GET"
        assert "query=" in req.url

    def test_post_method(self) -> None:
        ph = GraphQLPlaceholder()
        config = GraphQLConfig(method="POST")
        req = ph.create_request(URL, "{ users { id } }", config, CLIENT)
        assert isinstance(req, GoHTTPRequest)
        assert req.method == "POST"
        assert req.content == "{ users { id } }"

    def test_get_preserves_existing_params(self) -> None:
        ph = GraphQLPlaceholder()
        config = GraphQLConfig(method="GET")
        req = ph.create_request("http://example.com?version=1", "{ q }", config, CLIENT)
        assert "version=" in req.url
        assert "query=" in req.url

    def test_invalid_method_in_config(self) -> None:
        ph = GraphQLPlaceholder()
        from gotestwaf.errors import BadPlaceholderConfigError
        with pytest.raises(BadPlaceholderConfigError):
            ph.new_placeholder_config({"method": "DELETE"})

    def test_missing_method_in_config(self) -> None:
        ph = GraphQLPlaceholder()
        from gotestwaf.errors import BadPlaceholderConfigError
        with pytest.raises(BadPlaceholderConfigError):
            ph.new_placeholder_config({})


class TestGRPC:
    def test_raises_on_create(self) -> None:
        ph = GRPCPlaceholder()
        with pytest.raises(RuntimeError):
            ph.create_request(URL, PAYLOAD, None, CLIENT)


class TestRawRequest:
    def test_basic_post(self) -> None:
        ph = RawRequestPlaceholder()
        config = RawRequestConfig(method="POST", path="/api/test", body="data={{payload}}")
        req = ph.create_request(URL, PAYLOAD, config, CLIENT)
        assert isinstance(req, GoHTTPRequest)
        assert req.method == "POST"
        assert "/api/test" in req.url
        assert PAYLOAD in str(req.content)

    def test_payload_in_url(self) -> None:
        ph = RawRequestPlaceholder()
        config = RawRequestConfig(method="GET", path="/api/{{payload}}/info")
        req = ph.create_request(URL, "test", config, CLIENT)
        assert "/api/test/info" in req.url

    def test_payload_in_headers(self) -> None:
        ph = RawRequestPlaceholder()
        config = RawRequestConfig(method="GET", path="/", headers={"X-Test": "{{payload}}"})
        req = ph.create_request(URL, "injected", config, CLIENT)
        assert req.headers.get("X-Test") == "injected"

    def test_config_parse(self) -> None:
        ph = RawRequestPlaceholder()
        config = ph.new_placeholder_config({
            "method": "POST",
            "path": "/test",
            "headers": {"Content-Type": "text/plain"},
            "body": "hello {{payload}}",
        })
        assert isinstance(config, RawRequestConfig)
        assert config.method == "POST"
        assert config.path == "/test"

    def test_missing_method_raises(self) -> None:
        ph = RawRequestPlaceholder()
        from gotestwaf.errors import BadPlaceholderConfigError
        with pytest.raises(BadPlaceholderConfigError):
            ph.new_placeholder_config({"path": "/test"})
