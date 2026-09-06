# -*- coding: utf-8 -*-
"""Hashing transforms: hash, hash-all, HMAC, CRC."""

from __future__ import annotations

import base64 as _b64
import hashlib
import hmac
import zlib

from ..transforms import (TransformError, TransformParam, parse_bytes_input,
                          register_transform)


# Algorithms we expose in the UI. Restricted to hashlib.algorithms_guaranteed
# plus a couple of extras if the OpenSSL build supports them.
_HASH_ALGOS = [
    "md5", "sha1",
    "sha224", "sha256", "sha384", "sha512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
    "blake2b", "blake2s",
]

# Try to expose ripemd160 if the local OpenSSL/libcrypto has it.
try:
    hashlib.new("ripemd160")
    _HASH_ALGOS.append("ripemd160")
except Exception:
    pass


_OUTPUT_FORMATS = ["hex", "HEX", "base64", "raw bytes"]


def _format_digest(digest: bytes, fmt: str) -> bytes:
    if fmt == "hex":
        return digest.hex().encode("ascii")
    if fmt == "HEX":
        return digest.hex().upper().encode("ascii")
    if fmt == "base64":
        return _b64.b64encode(digest)
    if fmt == "raw bytes":
        return digest
    raise TransformError(f"Unknown output format: {fmt}")


# ── single-algorithm hash ──────────────────────────────────────────

@register_transform(
    name="Hash",
    category="Hashing",
    params=[
        TransformParam("algo", "Algorithm", "choice",
                       choices=_HASH_ALGOS, default="sha256"),
        TransformParam("output", "Output", "choice",
                       choices=_OUTPUT_FORMATS, default="hex"),
    ],
    help="Compute a cryptographic hash over the selection.",
)
def hash_one(data: bytes, params: dict) -> bytes:
    algo = params.get("algo", "sha256")
    try:
        h = hashlib.new(algo)
    except ValueError as e:
        raise TransformError(f"Unsupported algorithm: {algo}") from e
    h.update(data)
    return _format_digest(h.digest(), params.get("output", "hex"))


# ── report: every common hash at once ─────────────────────────────

@register_transform(
    name="Hash digest (all)",
    category="Hashing",
    help="Compute MD5, SHA1, SHA256, SHA512, CRC32 and size at once.",
)
def hash_all(data: bytes, params: dict) -> bytes:
    lines = [
        f"size:    {len(data)} bytes",
        f"md5:     {hashlib.md5(data).hexdigest()}",
        f"sha1:    {hashlib.sha1(data).hexdigest()}",
        f"sha256:  {hashlib.sha256(data).hexdigest()}",
        f"sha512:  {hashlib.sha512(data).hexdigest()}",
        f"crc32:   {zlib.crc32(data) & 0xFFFFFFFF:08x}",
        f"adler32: {zlib.adler32(data) & 0xFFFFFFFF:08x}",
    ]
    return "\n".join(lines).encode("ascii")


# ── HMAC ──────────────────────────────────────────────────────────

@register_transform(
    name="HMAC",
    category="Hashing",
    params=[
        TransformParam("algo", "Algorithm", "choice",
                       choices=_HASH_ALGOS, default="sha256"),
        TransformParam("key", "Key", "hex",
                       placeholder="0xAA... or \"secret\"",
                       help="Hex or quoted text key."),
        TransformParam("output", "Output", "choice",
                       choices=_OUTPUT_FORMATS, default="hex"),
    ],
    help="Keyed-hash MAC over the selection.",
)
def hmac_op(data: bytes, params: dict) -> bytes:
    key = parse_bytes_input(params.get("key", ""))
    if not key:
        raise TransformError("HMAC requires a non-empty key.")
    algo = params.get("algo", "sha256")
    try:
        mac = hmac.new(key, data, algo)
    except ValueError as e:
        raise TransformError(f"Unsupported algorithm: {algo}") from e
    return _format_digest(mac.digest(), params.get("output", "hex"))


# ── CRC family ────────────────────────────────────────────────────

@register_transform(
    name="CRC / checksum",
    category="Hashing",
    params=[
        TransformParam("algo", "Algorithm", "choice",
                       choices=["crc32", "adler32"], default="crc32"),
        TransformParam("output", "Output", "choice",
                       choices=["hex", "HEX", "decimal",
                                "raw bytes (big endian)",
                                "raw bytes (little endian)"],
                       default="hex"),
    ],
    help="32-bit checksum of the selection.",
)
def crc_op(data: bytes, params: dict) -> bytes:
    algo = params.get("algo", "crc32")
    if algo == "crc32":
        value = zlib.crc32(data) & 0xFFFFFFFF
    elif algo == "adler32":
        value = zlib.adler32(data) & 0xFFFFFFFF
    else:
        raise TransformError(f"Unknown CRC algorithm: {algo}")
    fmt = params.get("output", "hex")
    if fmt == "hex":
        return f"{value:08x}".encode("ascii")
    if fmt == "HEX":
        return f"{value:08X}".encode("ascii")
    if fmt == "decimal":
        return str(value).encode("ascii")
    if fmt == "raw bytes (big endian)":
        return value.to_bytes(4, "big")
    if fmt == "raw bytes (little endian)":
        return value.to_bytes(4, "little")
    raise TransformError(f"Unknown output format: {fmt}")
