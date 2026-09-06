# -*- coding: utf-8 -*-
"""Binary diffing engine for the hex editor.

Computes byte-level differences between two HexDataBuffers and exposes
the result as a sorted list of ``(start, end_exclusive)`` ranges that
the hex painter can use for highlighting and the diff window can use
for next/previous navigation.

Design pattern: **Model** — pure data, no Qt dependency aside from
its consumers.  Region computation runs in a single pass with a
chunked fast path so 100MB+ files diff in seconds rather than minutes.
"""

from __future__ import annotations

from .hex_data_buffer import HexDataBuffer


# Chunk size for the fast-path equality check
_CHUNK_SIZE = 64 * 1024


class BinaryDiffModel:
    """Compares two ``HexDataBuffer``s byte-by-byte.

    Trailing bytes (when the two files differ in length) are treated
    as one big diff region at the end of the longer file.

    Public attributes:
        buf_a, buf_b: the two buffers (left, right)
        regions: sorted list of ``(start, end_exclusive)`` diff ranges
        common_size: min(size_a, size_b)
        size_a, size_b: convenience accessors
    """

    def __init__(self, buf_a: HexDataBuffer, buf_b: HexDataBuffer):
        self.buf_a = buf_a
        self.buf_b = buf_b
        self.size_a = buf_a.size()
        self.size_b = buf_b.size()
        self.common_size = min(self.size_a, self.size_b)
        self.regions: list[tuple[int, int]] = []
        self._compute()

    # ── Region computation ─────────────────────────────────────────

    def _compute(self):
        """Build the diff region list in a single linear pass."""
        regions: list[tuple[int, int]] = []
        in_diff = False
        diff_start = 0

        off = 0
        while off < self.common_size:
            chunk_len = min(_CHUNK_SIZE, self.common_size - off)
            a = self.buf_a.read(off, chunk_len)
            b = self.buf_b.read(off, chunk_len)

            if a == b:
                # Whole chunk matches — close any open diff region
                if in_diff:
                    regions.append((diff_start, off))
                    in_diff = False
            else:
                # Slow path — scan byte by byte within this chunk
                for j in range(chunk_len):
                    if a[j] != b[j]:
                        if not in_diff:
                            diff_start = off + j
                            in_diff = True
                    else:
                        if in_diff:
                            regions.append((diff_start, off + j))
                            in_diff = False
            off += chunk_len

        if in_diff:
            regions.append((diff_start, self.common_size))

        # Trailing bytes — bytes that exist in only one file
        if self.size_a != self.size_b:
            regions.append((self.common_size, max(self.size_a, self.size_b)))

        self.regions = regions

    # ── Statistics ─────────────────────────────────────────────────

    def diff_byte_count(self) -> int:
        """Total number of byte positions that differ."""
        return sum(end - start for start, end in self.regions)

    def region_count(self) -> int:
        return len(self.regions)

    def summary(self) -> str:
        """Human-readable diff summary for the status bar."""
        if not self.regions:
            if self.size_a == self.size_b:
                return f"Files identical ({self.size_a:,} bytes)"
            return f"Files identical so far but different lengths"
        n_regions = len(self.regions)
        n_bytes = self.diff_byte_count()
        if self.size_a != self.size_b:
            extra = abs(self.size_a - self.size_b)
            return (f"{n_regions} diff region(s), {n_bytes:,} byte(s) differ "
                    f"\u2014 size mismatch +{extra:,}")
        return (f"{n_regions} diff region(s), {n_bytes:,} byte(s) differ "
                f"({100.0 * n_bytes / max(self.size_a, 1):.2f}%)")

    # ── Navigation ─────────────────────────────────────────────────

    def next_diff(self, from_offset: int) -> int | None:
        """Return start offset of the first diff region > from_offset.

        Wraps to the beginning if at the end.
        """
        if not self.regions:
            return None
        for start, _end in self.regions:
            if start > from_offset:
                return start
        return self.regions[0][0]  # wrap

    def prev_diff(self, from_offset: int) -> int | None:
        """Return start offset of the last diff region < from_offset.

        Wraps to the end if at the beginning.
        """
        if not self.regions:
            return None
        for start, _end in reversed(self.regions):
            if start < from_offset:
                return start
        return self.regions[-1][0]  # wrap

    # ── Range query for painter ────────────────────────────────────

    def diff_offsets_in_range(self, lo: int, hi: int) -> set[int]:
        """Return set of diff byte offsets in ``[lo, hi)``.

        Used by HexWidget.paintEvent to compute only the offsets the
        painter will actually need (the visible window), avoiding
        huge memory usage for files with millions of diff bytes.
        """
        out: set[int] = set()
        for r_start, r_end in self.regions:
            if r_end <= lo:
                continue
            if r_start >= hi:
                break  # regions are sorted ascending
            for off in range(max(r_start, lo), min(r_end, hi)):
                out.add(off)
        return out
