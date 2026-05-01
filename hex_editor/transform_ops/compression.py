# -*- coding: utf-8 -*-
"""Compression / decompression transforms.

Algorithms: gzip, zlib, raw deflate, bzip2, LZMA, LZ4, zstd.
LZ4 and zstd require external packages (``pip install lz4 zstandard``);
all others use the Python standard library.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import zlib

from ..transforms import TransformError, TransformParam, register_transform


# ── Helpers for lenient decompression ─────────────────────────────

def _info(msg: str):
    """Print info to stdout — visible in the transform dialog's Debug pane."""
    print(f"[info] {msg}")


def _gzip_lenient(data: bytes, base_offset: int = 0) -> bytes:
    """Decompress gzip, tolerating truncated streams."""
    strict = False
    try:
        result = gzip.decompress(data)
        strict = True
    except Exception:
        result = b''

    if strict:
        _info(f"Stream start: 0x{base_offset:08X}, "
              f"stream end: 0x{base_offset + len(data) - 1:08X}, "
              f"compressed: {len(data)} bytes -> decompressed: {len(result)} bytes")
        return result

    # Use decompressobj for partial/truncated streams
    d = zlib.decompressobj(zlib.MAX_WBITS | 16)  # 16 = gzip mode
    try:
        out = d.decompress(data)
        consumed = len(data) - len(d.unused_data)
        try:
            out += d.flush()
        except Exception:
            pass
        if out:
            _info(f"Stream start: 0x{base_offset:08X}, "
                  f"consumed: ~{consumed} bytes (stream may be truncated), "
                  f"decompressed: {len(out)} bytes (PARTIAL)")
            return out
    except Exception:
        pass
    raise TransformError("Gzip decompress failed (data may be corrupt)")


def _zlib_lenient(data: bytes, wbits=zlib.MAX_WBITS,
                  base_offset: int = 0) -> bytes:
    """Decompress zlib/deflate, tolerating truncated streams."""
    strict = False
    try:
        result = zlib.decompress(data, wbits)
        strict = True
    except Exception:
        result = b''

    if strict:
        _info(f"Stream start: 0x{base_offset:08X}, "
              f"stream end: 0x{base_offset + len(data) - 1:08X}, "
              f"compressed: {len(data)} bytes -> decompressed: {len(result)} bytes")
        return result

    d = zlib.decompressobj(wbits)
    try:
        out = d.decompress(data)
        consumed = len(data) - len(d.unused_data)
        try:
            out += d.flush()
        except Exception:
            pass
        if out:
            _info(f"Stream start: 0x{base_offset:08X}, "
                  f"consumed: ~{consumed} bytes (stream may be truncated), "
                  f"decompressed: {len(out)} bytes (PARTIAL)")
            return out
    except Exception:
        pass
    raise TransformError("Zlib/deflate decompress failed")

# ── gzip ──────────────────────────────────────────────────────────

@register_transform(
    name="Gzip compress",
    category="Compression",
    length_preserving=False,
    help="Compress data using gzip (RFC 1952).",
)
def gzip_compress(data: bytes, params: dict) -> bytes:
    try:
        return gzip.compress(data)
    except Exception as e:
        raise TransformError(f"Gzip compress: {e}") from e


@register_transform(
    name="Gzip decompress",
    category="Compression",
    length_preserving=False,
    help="Decompress gzip data. Auto-scans for \\x1f\\x8b header. "
         "Tolerates truncated streams. Check Debug pane for stream offsets.",
)
def gzip_decompress(data: bytes, params: dict) -> bytes:
    # Try as-is (offset 0)
    try:
        return _gzip_lenient(data, base_offset=0)
    except TransformError:
        pass
    # Scan for gzip magic
    idx = data.find(b'\x1f\x8b')
    if idx > 0:
        _info(f"Gzip header found at offset 0x{idx:08X} "
              f"(skipped {idx} leading bytes)")
        try:
            return _gzip_lenient(data[idx:], base_offset=idx)
        except TransformError as e:
            raise
    raise TransformError("Gzip decompress: no gzip header (\\x1f\\x8b) found")


# ── zlib ──────────────────────────────────────────────────────────

@register_transform(
    name="Zlib compress",
    category="Compression",
    length_preserving=False,
    help="Compress data using zlib (RFC 1950).",
)
def zlib_compress(data: bytes, params: dict) -> bytes:
    try:
        return zlib.compress(data)
    except Exception as e:
        raise TransformError(f"Zlib compress: {e}") from e


@register_transform(
    name="Zlib decompress",
    category="Compression",
    length_preserving=False,
    help="Decompress zlib data. Tries zlib, raw deflate, scans for headers. "
         "Tolerates truncation. Check Debug pane for stream offsets.",
)
def zlib_decompress(data: bytes, params: dict) -> bytes:
    try:
        return _zlib_lenient(data, base_offset=0)
    except TransformError:
        pass
    try:
        return _zlib_lenient(data, -15, base_offset=0)
    except TransformError:
        pass
    for magic in (b'\x78\x9c', b'\x78\x01', b'\x78\x5e', b'\x78\xda'):
        idx = data.find(magic)
        if idx >= 0:
            _info(f"Zlib header 0x{magic.hex()} found at offset 0x{idx:08X}")
            try:
                return _zlib_lenient(data[idx:], base_offset=idx)
            except TransformError:
                continue
    raise TransformError("Zlib decompress: no valid zlib/deflate stream found")


# ── raw deflate ───────────────────────────────────────────────────

@register_transform(
    name="Deflate compress (raw)",
    category="Compression",
    length_preserving=False,
    help="Compress using raw deflate (no zlib/gzip header).",
)
def deflate_compress(data: bytes, params: dict) -> bytes:
    try:
        obj = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
        return obj.compress(data) + obj.flush()
    except Exception as e:
        raise TransformError(f"Deflate compress: {e}") from e


@register_transform(
    name="Deflate decompress (raw)",
    category="Compression",
    length_preserving=False,
    help="Decompress raw deflate data (no header). Tolerates truncation. "
         "Check Debug pane for stream offsets.",
)
def deflate_decompress(data: bytes, params: dict) -> bytes:
    try:
        return _zlib_lenient(data, -15, base_offset=0)
    except TransformError as e:
        raise TransformError(f"Deflate decompress: {e}") from e


# ── bzip2 ─────────────────────────────────────────────────────────

@register_transform(
    name="Bzip2 compress",
    category="Compression",
    length_preserving=False,
    help="Compress data using bzip2.",
)
def bzip2_compress(data: bytes, params: dict) -> bytes:
    try:
        return bz2.compress(data)
    except Exception as e:
        raise TransformError(f"Bzip2 compress: {e}") from e


@register_transform(
    name="Bzip2 decompress",
    category="Compression",
    length_preserving=False,
    help="Decompress bzip2 data. Scans for BZh magic. Check Debug pane for offsets.",
)
def bzip2_decompress(data: bytes, params: dict) -> bytes:
    try:
        result = bz2.decompress(data)
        _info(f"Stream start: 0x00000000, "
              f"compressed: {len(data)} bytes -> decompressed: {len(result)} bytes")
        return result
    except Exception:
        pass
    idx = data.find(b'BZh')
    if idx > 0:
        _info(f"Bzip2 header found at offset 0x{idx:08X}")
        try:
            result = bz2.decompress(data[idx:])
            _info(f"Stream start: 0x{idx:08X}, "
                  f"compressed: {len(data) - idx} bytes -> decompressed: {len(result)} bytes")
            return result
        except Exception as e:
            raise TransformError(f"Bzip2 decompress: header at offset 0x{idx:08X} but: {e}") from e
    raise TransformError("Bzip2 decompress: no bzip2 header (BZh) found")


# ── LZMA / XZ ────────────────────────────────────────────────────

@register_transform(
    name="LZMA compress",
    category="Compression",
    length_preserving=False,
    help="Compress data using LZMA (raw .lzma format).",
)
def lzma_compress(data: bytes, params: dict) -> bytes:
    try:
        return lzma.compress(data, format=lzma.FORMAT_ALONE)
    except Exception as e:
        raise TransformError(f"LZMA compress: {e}") from e


@register_transform(
    name="LZMA decompress",
    category="Compression",
    length_preserving=False,
    help="Decompress LZMA data. Auto-detects .lzma/.xz, scans for headers. "
         "Check Debug pane for offsets.",
)
def lzma_decompress(data: bytes, params: dict) -> bytes:
    try:
        result = lzma.decompress(data)
        _info(f"Stream start: 0x00000000, "
              f"compressed: {len(data)} bytes -> decompressed: {len(result)} bytes")
        return result
    except Exception:
        pass
    # Scan for XZ magic
    xz_magic = b'\xfd7zXZ\x00'
    idx = data.find(xz_magic)
    if idx >= 0:
        _info(f"XZ header found at offset 0x{idx:08X}")
        try:
            result = lzma.decompress(data[idx:])
            _info(f"Stream start: 0x{idx:08X}, "
                  f"compressed: {len(data) - idx} bytes -> decompressed: {len(result)} bytes")
            return result
        except Exception as e:
            raise TransformError(f"LZMA decompress: XZ header at 0x{idx:08X} but: {e}") from e
    # Try LZMA_ALONE at small offsets
    for off in range(min(16, len(data))):
        try:
            result = lzma.decompress(data[off:], format=lzma.FORMAT_ALONE)
            _info(f"LZMA stream found at offset 0x{off:08X}, "
                  f"compressed: {len(data) - off} bytes -> decompressed: {len(result)} bytes")
            return result
        except Exception:
            continue
    raise TransformError("LZMA decompress: no valid LZMA/XZ stream found")


@register_transform(
    name="XZ compress",
    category="Compression",
    length_preserving=False,
    help="Compress data using XZ (LZMA2 with .xz container).",
)
def xz_compress(data: bytes, params: dict) -> bytes:
    try:
        return lzma.compress(data, format=lzma.FORMAT_XZ)
    except Exception as e:
        raise TransformError(f"XZ compress: {e}") from e


@register_transform(
    name="XZ decompress",
    category="Compression",
    length_preserving=False,
    help="Decompress XZ (.xz) data.",
)
def xz_decompress(data: bytes, params: dict) -> bytes:
    try:
        return lzma.decompress(data, format=lzma.FORMAT_XZ)
    except Exception as e:
        raise TransformError(f"XZ decompress: {e}") from e


# ── LZ4 (external: pip install lz4) ──────────────────────────────

@register_transform(
    name="LZ4 compress",
    category="Compression",
    length_preserving=False,
    help="Compress using LZ4 frame format. Requires: pip install lz4",
)
def lz4_compress(data: bytes, params: dict) -> bytes:
    try:
        import lz4.frame
        return lz4.frame.compress(data)
    except ImportError:
        raise TransformError("lz4 package not installed. Run: pip install lz4")
    except Exception as e:
        raise TransformError(f"LZ4 compress: {e}") from e


@register_transform(
    name="LZ4 decompress",
    category="Compression",
    length_preserving=False,
    help="Decompress LZ4 frame data. Requires: pip install lz4",
)
def lz4_decompress(data: bytes, params: dict) -> bytes:
    try:
        import lz4.frame
        return lz4.frame.decompress(data)
    except ImportError:
        raise TransformError("lz4 package not installed. Run: pip install lz4")
    except Exception as e:
        raise TransformError(f"LZ4 decompress: {e}") from e


# ── Zstandard (external: pip install zstandard) ───────────────────

@register_transform(
    name="Zstd compress",
    category="Compression",
    length_preserving=False,
    help="Compress using Zstandard. Requires: pip install zstandard",
)
def zstd_compress(data: bytes, params: dict) -> bytes:
    try:
        import zstandard as zstd
        cctx = zstd.ZstdCompressor()
        return cctx.compress(data)
    except ImportError:
        raise TransformError(
            "zstandard package not installed. Run: pip install zstandard")
    except Exception as e:
        raise TransformError(f"Zstd compress: {e}") from e


@register_transform(
    name="Zstd decompress",
    category="Compression",
    length_preserving=False,
    help="Decompress Zstandard data. Requires: pip install zstandard",
)
def zstd_decompress(data: bytes, params: dict) -> bytes:
    try:
        import zstandard as zstd
        dctx = zstd.ZstdDecompressor()
        return dctx.decompress(data, max_output_size=100 * 1024 * 1024)
    except ImportError:
        raise TransformError(
            "zstandard package not installed. Run: pip install zstandard")
    except Exception as e:
        raise TransformError(f"Zstd decompress: {e}") from e
