"""XML entity encoder implementation.

Matches Go's xml.NewEncoder(b).Encode(data) behavior which wraps the
string in XML tags and escapes XML entities.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from xml.etree.ElementTree import Element, tostring


@dataclass(slots=True)
class XMLEntityEncoder:
    """Encodes data as XML entities using Go-compatible XML serialization.

    Go's xml.NewEncoder.Encode for a string produces <string>escaped_data</string>.
    We replicate this exact behavior for payload parity.
    """

    name: str = "XMLEntity"

    def get_name(self) -> str:
        return self.name

    def encode(self, data: str) -> str:
        # Go's xml.Encode wraps string in <string>...</string> with entity escaping.
        # xml.etree.ElementTree.tostring does the same: creates <string>escaped</string>
        elem = Element("string")
        elem.text = data
        # tostring returns bytes by default, decode to str.
        # short_empty_elements=False ensures <string></string> not <string/>
        result = tostring(elem, encoding="unicode", short_empty_elements=False)
        # Go's xml.Encoder appends a newline; match that
        return result + "\n"


default_xmlentity_encoder = XMLEntityEncoder()
