"""SOAPBody placeholder - places payload in a SOAP envelope."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gotestwaf.payload.encoder.encoder import apply_encoder
from gotestwaf.payload.placeholder.placeholder import PlaceholderConfig
from gotestwaf.payload.placeholder.utils import random_hex
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest, Request

SEED = 5

SOAP_BODY_PAYLOAD_WRAPPER = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"\n'
    '\txmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
    '\t<soapenv:Header>\n'
    '\t\t<ns1:RequestHeader soapenv:actor="http://schemas.xmlsoap.org/soap/actor/next"\n'
    '\t\t\tsoapenv:mustUnderstand="0" xmlns:ns1="https://www.google.com/apis/ads/publisher/v202002">\n'
    '\t\t</ns1:RequestHeader>\n'
    '\t</soapenv:Header>\n'
    '\t<soapenv:Body>\n'
    '\t\t<getAdUnitsByStatement xmlns="https://www.google.com/apis/ads/publisher/v202002">\n'
    '\t\t\t<filterStatement>\n'
    '\t\t\t\t<{tag}>{payload}</{tag}>\n'
    '\t\t\t</filterStatement>\n'
    '\t\t</getAdUnitsByStatement>\n'
    '\t</soapenv:Body>\n'
    '</soapenv:Envelope>'
)


@dataclass(slots=True)
class SOAPBodyPlaceholder:
    """Places payload in a SOAP body envelope."""

    name: str = "SOAPBody"

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
        from xml.sax.saxutils import escape as xml_escape
        param = "ab" + random_hex(SEED)
        # Only XML-escape if the payload still contains raw XML-meaningful characters.
        # If it's already entity-encoded (XMLEntity encoder) or percent-encoded (URL),
        # re-escaping turns &lt;script&gt; into &amp;lt;script&amp;gt; and breaks the test.
        looks_already_escaped = ("&lt;" in payload) or ("&gt;" in payload) or ("&amp;" in payload)
        encoded_payload = payload if looks_already_escaped else xml_escape(payload)
        soap_payload = SOAP_BODY_PAYLOAD_WRAPPER.format(tag=param, payload=encoded_payload)

        return GoHTTPRequest(
            method="POST",
            url=request_url,
            headers={
                "SOAPAction": '"http://schemas.xmlsoap.org/soap/actor/next"',
                "Content-Type": "text/xml",
            },
            content=soap_payload,
        )


default_soap_body = SOAPBodyPlaceholder()
