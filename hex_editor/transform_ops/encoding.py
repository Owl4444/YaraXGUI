# -*- coding: utf-8 -*-
"""Encoding transforms: Base64, Hex."""

from __future__ import annotations

import base64
import binascii

from ..transforms import TransformError, register_transform


@register_transform(
    name="Base64 encode",
    category="Encoding",
    length_preserving=False,
)
def base64_encode(data: bytes, params: dict) -> bytes:
    return base64.b64encode(data)


@register_transform(
    name="Base64 decode",
    category="Encoding",
    length_preserving=False,
)
def base64_decode(data: bytes, params: dict) -> bytes:
    try:
        # Allow whitespace/padding leniency
        cleaned = bytes(b for b in data if b not in b"\r\n\t ")
        # Pad if needed
        pad = (-len(cleaned)) % 4
        if pad:
            cleaned += b"=" * pad
        return base64.b64decode(cleaned, validate=False)
    except binascii.Error as e:
        raise TransformError(f"Base64 decode failed: {e}") from e


@register_transform(
    name="Hex encode",
    category="Encoding",
    length_preserving=False,
)
def hex_encode(data: bytes, params: dict) -> bytes:
    return data.hex().encode("ascii")


@register_transform(
    name="Hex decode",
    category="Encoding",
    length_preserving=False,
)
def hex_decode(data: bytes, params: dict) -> bytes:
    try:
        cleaned = bytes(b for b in data if b not in b"\r\n\t ").decode("ascii")
        return bytes.fromhex(cleaned)
    except (ValueError, UnicodeDecodeError) as e:
        raise TransformError(f"Hex decode failed: {e}") from e
