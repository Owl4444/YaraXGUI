# -*- coding: utf-8 -*-
"""Symmetric crypto transforms: RC4, AES (ECB/CBC/CTR/GCM), ChaCha20.

All ``pycryptodome`` imports are deferred until the function actually runs
so the rest of the hex editor still works if the package is missing —
only these specific operations will fail with an actionable error.
"""

from __future__ import annotations

from ..transforms import (TransformError, TransformParam, parse_bytes_input,
                          register_transform)


_AES_MODES = ["ECB", "CBC", "CTR", "GCM"]
_PADDINGS = ["PKCS7", "None"]


def _aes_key_for_mode(key: bytes) -> bytes:
    if len(key) not in (16, 24, 32):
        raise TransformError(
            f"AES key must be 16/24/32 bytes (got {len(key)})."
        )
    return key


@register_transform(
    name="RC4 encrypt/decrypt",
    category="Symmetric crypto",
    params=[
        TransformParam("key", "Key", "hex",
                       placeholder="0xDEADBEEF or \"secret\""),
    ],
    length_preserving=True,
)
def rc4(data: bytes, params: dict) -> bytes:
    key = parse_bytes_input(params.get("key", ""))
    if not key:
        raise TransformError("RC4 requires a non-empty key.")
    try:
        from Crypto.Cipher import ARC4
    except ImportError as e:
        raise TransformError(
            "pycryptodome is required for RC4. Install with `pip install pycryptodome`."
        ) from e
    cipher = ARC4.new(key)
    return cipher.encrypt(data)


@register_transform(
    name="AES encrypt",
    category="Symmetric crypto",
    params=[
        TransformParam("key", "Key", "hex",
                       placeholder="16/24/32 bytes hex"),
        TransformParam("iv", "IV / Nonce", "hex",
                       placeholder="16 bytes (CBC) or nonce (CTR/GCM)"),
        TransformParam("mode", "Mode", "choice",
                       default="CBC", choices=_AES_MODES),
        TransformParam("padding", "Padding", "choice",
                       default="PKCS7", choices=_PADDINGS),
    ],
    length_preserving=False,
    help="CBC adds up to 16 bytes of padding. GCM appends a 16-byte tag.",
)
def aes_encrypt(data: bytes, params: dict) -> bytes:
    key = _aes_key_for_mode(parse_bytes_input(params.get("key", "")))
    mode = (params.get("mode") or "CBC").upper()
    iv = parse_bytes_input(params.get("iv", ""))
    padding = (params.get("padding") or "PKCS7").upper()
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
    except ImportError as e:
        raise TransformError(
            "pycryptodome is required for AES. Install with `pip install pycryptodome`."
        ) from e

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        block = data if padding == "NONE" else pad(data, AES.block_size)
        if padding == "NONE" and len(block) % AES.block_size != 0:
            raise TransformError(
                f"AES-ECB with no padding requires multiple of {AES.block_size} bytes."
            )
        return cipher.encrypt(block)
    if mode == "CBC":
        if len(iv) != 16:
            raise TransformError("AES-CBC requires a 16-byte IV.")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        block = data if padding == "NONE" else pad(data, AES.block_size)
        if padding == "NONE" and len(block) % AES.block_size != 0:
            raise TransformError(
                f"AES-CBC with no padding requires multiple of {AES.block_size} bytes."
            )
        return cipher.encrypt(block)
    if mode == "CTR":
        if len(iv) not in (8, 16):
            raise TransformError("AES-CTR requires an 8- or 16-byte nonce.")
        # Full 16-byte initial counter block → nonce + counter=0
        if len(iv) == 16:
            cipher = AES.new(key, AES.MODE_CTR, initial_value=iv, nonce=b"")
        else:
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
        return cipher.encrypt(data)
    if mode == "GCM":
        if len(iv) == 0:
            raise TransformError("AES-GCM requires a non-empty nonce.")
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ct, tag = cipher.encrypt_and_digest(data)
        return ct + tag  # 16-byte tag appended
    raise TransformError(f"Unsupported AES mode: {mode}")


@register_transform(
    name="AES decrypt",
    category="Symmetric crypto",
    params=[
        TransformParam("key", "Key", "hex",
                       placeholder="16/24/32 bytes hex"),
        TransformParam("iv", "IV / Nonce", "hex",
                       placeholder="16 bytes (CBC) or nonce (CTR/GCM)"),
        TransformParam("mode", "Mode", "choice",
                       default="CBC", choices=_AES_MODES),
        TransformParam("padding", "Padding", "choice",
                       default="PKCS7", choices=_PADDINGS),
    ],
    length_preserving=False,
    help="For GCM, include the trailing 16-byte tag in the selection.",
)
def aes_decrypt(data: bytes, params: dict) -> bytes:
    key = _aes_key_for_mode(parse_bytes_input(params.get("key", "")))
    mode = (params.get("mode") or "CBC").upper()
    iv = parse_bytes_input(params.get("iv", ""))
    padding = (params.get("padding") or "PKCS7").upper()
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except ImportError as e:
        raise TransformError(
            "pycryptodome is required for AES. Install with `pip install pycryptodome`."
        ) from e

    try:
        if mode == "ECB":
            if len(data) % AES.block_size != 0:
                raise TransformError("AES-ECB ciphertext must be a multiple of 16 bytes.")
            cipher = AES.new(key, AES.MODE_ECB)
            pt = cipher.decrypt(data)
            return pt if padding == "NONE" else unpad(pt, AES.block_size)
        if mode == "CBC":
            if len(iv) != 16:
                raise TransformError("AES-CBC requires a 16-byte IV.")
            if len(data) % AES.block_size != 0:
                raise TransformError("AES-CBC ciphertext must be a multiple of 16 bytes.")
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = cipher.decrypt(data)
            return pt if padding == "NONE" else unpad(pt, AES.block_size)
        if mode == "CTR":
            if len(iv) not in (8, 16):
                raise TransformError("AES-CTR requires an 8- or 16-byte nonce.")
            if len(iv) == 16:
                cipher = AES.new(key, AES.MODE_CTR, initial_value=iv, nonce=b"")
            else:
                cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
            return cipher.decrypt(data)
        if mode == "GCM":
            if len(iv) == 0:
                raise TransformError("AES-GCM requires a non-empty nonce.")
            if len(data) < 16:
                raise TransformError(
                    "AES-GCM ciphertext must include the trailing 16-byte tag."
                )
            ct, tag = data[:-16], data[-16:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            return cipher.decrypt_and_verify(ct, tag)
    except TransformError:
        raise
    except Exception as e:
        raise TransformError(f"AES decrypt failed: {e}") from e
    raise TransformError(f"Unsupported AES mode: {mode}")


@register_transform(
    name="ChaCha20",
    category="Symmetric crypto",
    params=[
        TransformParam("key", "Key", "hex",
                       placeholder="32 bytes hex"),
        TransformParam("nonce", "Nonce", "hex",
                       placeholder="8 or 12 bytes hex"),
    ],
    length_preserving=True,
)
def chacha20(data: bytes, params: dict) -> bytes:
    key = parse_bytes_input(params.get("key", ""))
    nonce = parse_bytes_input(params.get("nonce", ""))
    if len(key) != 32:
        raise TransformError(f"ChaCha20 key must be 32 bytes (got {len(key)}).")
    if len(nonce) not in (8, 12):
        raise TransformError(f"ChaCha20 nonce must be 8 or 12 bytes (got {len(nonce)}).")
    try:
        from Crypto.Cipher import ChaCha20 as _ChaCha20
    except ImportError as e:
        raise TransformError(
            "pycryptodome is required for ChaCha20. Install with `pip install pycryptodome`."
        ) from e
    cipher = _ChaCha20.new(key=key, nonce=nonce)
    return cipher.encrypt(data)
