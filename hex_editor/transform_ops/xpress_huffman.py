"""Bounded, portable decoder for raw COMPRESSION_FORMAT_XPRESS_HUFF (4).

Implemented from MS-XCA section 2.2.4, with the Windows 32-bit match-length
extension clarified by Microsoft's protocol team. No container headers are
parsed here. See docs/XPRESS_HUFFMAN.md for sources and format limitations.
"""

from __future__ import annotations

from time import monotonic

from ..transforms import TransformError, TransformParam, register_transform

MAX_OUTPUT_SIZE = 64 * 1024 * 1024
MAX_DECODE_SECONDS = 2.0


class _Input:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.bits = 0
        self.extra = 0

    def read(self, count: int) -> bytes:
        end = self.pos + count
        if end > len(self.data):
            raise TransformError(
                f"XPRESS Huffman: truncated input at byte {self.pos}. "
                "Select the complete compressed payload and check Expected size."
            )
        result = self.data[self.pos:end]
        self.pos = end
        return result

    def uint(self, count: int) -> int:
        return int.from_bytes(self.read(count), "little")

    def start_bits(self) -> None:
        # Two little-endian words, read most-significant bit first.
        self.bits = (self.uint(2) << 16) | self.uint(2)
        self.extra = 16

    def consume(self, count: int) -> None:
        self.bits = (self.bits << count) & 0xFFFFFFFF
        self.extra -= count
        if self.extra < 0:
            self.bits |= self.uint(2) << -self.extra
            self.extra += 16


def _decoding_table(header: bytes) -> tuple[list[int], list[int]]:
    lengths = [n for byte in header for n in (byte & 15, byte >> 4)]
    # A direct 15-bit lookup avoids a Python tree walk for every output byte.
    table: list[int] = []
    for width in range(1, 16):
        for symbol, length in enumerate(lengths):
            if length != width:
                continue
            count = 1 << (15 - width)
            if len(table) + count > 32768:
                raise TransformError("XPRESS Huffman: oversubscribed Huffman table.")
            table.extend([symbol] * count)
    if len(table) != 32768:
        raise TransformError("XPRESS Huffman: incomplete or empty Huffman table.")
    return table, lengths


def decompress(data: bytes, expected_size: int, *,
               max_output_size: int = MAX_OUTPUT_SIZE,
               time_limit: float = MAX_DECODE_SECONDS) -> bytes:
    """Decode exactly *expected_size* bytes, rejecting unsafe reads and writes.

    As with the Windows API, the caller supplies the original size. Symbol 256
    is a normal distance-1, length-3 match until that size is reached; using it
    alone as an EOF sentinel silently truncates valid streams. Padding and an
    optional EOF after the requested output are not interpreted as more data.
    """
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
        raise TransformError("XPRESS Huffman: Expected size must be a non-negative integer.")
    if expected_size > max_output_size:
        raise TransformError(
            f"XPRESS Huffman: output exceeds the {max_output_size:,}-byte limit."
        )
    if expected_size == 0:
        if data:
            raise TransformError("XPRESS Huffman: nonempty input requires a positive Expected size.")
        return b""

    deadline = monotonic() + time_limit
    source = _Input(data)
    output = bytearray()
    symbols = 0
    while len(output) < expected_size:
        if monotonic() >= deadline:
            raise TransformError("XPRESS Huffman: decompression time limit exceeded (2 seconds).")
        table, lengths = _decoding_table(source.read(256))
        source.start_bits()
        block_end = len(output) + 65536
        while len(output) < min(block_end, expected_size):
            # Check periodically even for literal-only or highly repetitive data.
            if symbols % 1024 == 0 and monotonic() >= deadline:
                raise TransformError("XPRESS Huffman: decompression time limit exceeded (2 seconds).")
            symbols += 1
            symbol = table[source.bits >> 17]
            source.consume(lengths[symbol])
            if symbol < 256:
                output.append(symbol)
                continue

            match = symbol - 256
            length = match & 15
            offset_bits = match >> 4
            if length == 15:
                length = source.uint(1)
                if length == 255:
                    length = source.uint(2)
                    # Windows also emits zero + uint32 for very long matches.
                    if length == 0:
                        length = source.uint(4)
                    if length < 15:
                        raise TransformError("XPRESS Huffman: invalid extended match length.")
                    length -= 15
                length += 15
            length += 3
            distance = (1 << offset_bits) + (source.bits >> (32 - offset_bits))
            source.consume(offset_bits)
            if distance > len(output):
                raise TransformError("XPRESS Huffman: match refers before the start of the output.")
            if length > expected_size - len(output):
                raise TransformError("XPRESS Huffman: match exceeds Expected size; check the original size.")
            # Matches may overlap themselves and cross a 64 KiB block boundary.
            # Expand in bounded pieces, keeping temporary allocations small.
            pattern = bytes(output[-distance:])
            remaining = length
            while remaining:
                if monotonic() >= deadline:
                    raise TransformError("XPRESS Huffman: decompression time limit exceeded (2 seconds).")
                count = min(remaining, max(distance, (65536 // distance) * distance))
                output.extend((pattern * ((count + distance - 1) // distance))[:count])
                remaining -= count
    return bytes(output)


@register_transform(
    name="XPRESS Huffman decompress",
    category="Compression",
    params=[TransformParam(
        key="expected_size", label="Expected size (bytes)", kind="text",
        placeholder="Original size, e.g. 65536 or 0x10000",
        help="Required: uncompressed byte count from the caller or container (maximum 64 MiB).",
    )],
    length_preserving=False,
    requires_full_input=True,
    help="Decompress a raw XPRESS Huffman payload (RtlDecompressBufferEx format 4). "
         "Enter its original size; remove any container header first. "
         "Portable, no additional packages. Limits: 64 MiB output and 2 seconds per run.",
)
def xpress_huffman_decompress(data: bytes, params: dict) -> bytes:
    value = str(params.get("expected_size", "")).strip()
    try:
        size = int(value, 16 if value.lower().startswith("0x") else 10)
    except ValueError as exc:
        raise TransformError(
            "XPRESS Huffman: enter Expected size in bytes (decimal or 0x hexadecimal). "
            "Raw streams do not store their original size."
        ) from exc
    return decompress(data, size)
