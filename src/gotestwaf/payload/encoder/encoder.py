"""Encoder interface and registry for payload encoding strategies."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from gotestwaf.errors import UnknownEncoderError


@runtime_checkable
class Encoder(Protocol):
    """Protocol for payload encoders."""

    def get_name(self) -> str: ...
    def encode(self, data: str) -> str: ...


# Registry populated by init
_encoders: dict[str, Encoder] = {}


def _init_encoders() -> None:
    """Initialize the encoder registry with all default encoders."""
    from gotestwaf.payload.encoder.base64 import (
        default_base64_encoder,
        default_base64_flat_encoder,
    )
    from gotestwaf.payload.encoder.jsunicode import default_jsunicode_encoder
    from gotestwaf.payload.encoder.plain import default_plain_encoder
    from gotestwaf.payload.encoder.url import default_url_encoder
    from gotestwaf.payload.encoder.xmlentity import default_xmlentity_encoder

    all_encoders: list[Encoder] = [
        default_base64_encoder,
        default_base64_flat_encoder,
        default_jsunicode_encoder,
        default_plain_encoder,
        default_url_encoder,
        default_xmlentity_encoder,
    ]

    for enc in all_encoders:
        _encoders[enc.get_name()] = enc


def get_encoders() -> dict[str, Encoder]:
    """Return the encoder registry, initializing if needed."""
    if not _encoders:
        _init_encoders()
    return _encoders


def apply_encoder(encoder_name: str, data: str) -> str:
    """Apply an encoder by name to the given data.

    Supports encoding chains via '+' separator (e.g., 'URL+Base64' applies
    URL first, then Base64). Single encoder names work as before.

    Args:
        encoder_name: Name of the encoder (or chain like 'URL+Base64').
        data: The data string to encode.

    Returns:
        The encoded string.

    Raises:
        UnknownEncoderError: If any encoder name in the chain is not recognized.
    """
    encoders = get_encoders()

    # Support encoding chains: "URL+Base64" applies URL first, then Base64
    if "+" in encoder_name:
        result = data
        for stage_name in encoder_name.split("+"):
            stage_name = stage_name.strip()
            enc = encoders.get(stage_name)
            if enc is None:
                raise UnknownEncoderError(stage_name)
            result = enc.encode(result)
        return result

    enc = encoders.get(encoder_name)
    if enc is None:
        raise UnknownEncoderError(encoder_name)

    return enc.encode(data)
