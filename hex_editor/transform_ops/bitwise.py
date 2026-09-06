# -*- coding: utf-8 -*-
"""Bitwise transforms: XOR, NOT, ROT13, Reverse."""

from __future__ import annotations

from ..transforms import (TransformError, TransformParam, parse_bytes_input,
                          register_transform)


@register_transform(
    name="XOR",
    category="Bitwise",
    params=[
        TransformParam("key", "Key", "hex",
                       placeholder="0xAA or \"hello\"",
                       help="Hex or quoted text key."),
    ],
    length_preserving=True,
)
def xor(data: bytes, params: dict) -> bytes:
    key = parse_bytes_input(params.get("key", ""))
    if not key:
        raise TransformError("XOR requires a non-empty key.")
    out = bytearray(len(data))
    klen = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % klen]
    return bytes(out)


@register_transform(
    name="NOT (bitwise)",
    category="Bitwise",
    length_preserving=True,
)
def not_bitwise(data: bytes, params: dict) -> bytes:
    return bytes(b ^ 0xFF for b in data)


@register_transform(
    name="ROT13",
    category="Bitwise",
    params=[
        TransformParam(
            "count", "Rotate by", "int", default="13",
            help="Number of positions to rotate each letter (default 13). "
                 "Negative values rotate left. Non-letters are left alone.",
        ),
    ],
    length_preserving=True,
    help="Caesar cipher over ASCII A-Z / a-z. Defaults to classic ROT13.",
)
def rot13(data: bytes, params: dict) -> bytes:
    try:
        count = int(params.get("count", 13))
    except (TypeError, ValueError) as e:
        raise TransformError(f"Invalid rotation count: {e}") from e
    shift = count % 26
    out = bytearray(len(data))
    for i, b in enumerate(data):
        if 0x41 <= b <= 0x5A:
            out[i] = 0x41 + (b - 0x41 + shift) % 26
        elif 0x61 <= b <= 0x7A:
            out[i] = 0x61 + (b - 0x61 + shift) % 26
        else:
            out[i] = b
    return bytes(out)


@register_transform(
    name="Reverse bytes",
    category="Bitwise",
    length_preserving=True,
)
def reverse_bytes(data: bytes, params: dict) -> bytes:
    return data[::-1]
