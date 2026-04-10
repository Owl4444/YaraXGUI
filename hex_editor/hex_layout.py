# -*- coding: utf-8 -*-
"""Layout metrics and coordinate mapping for the hex editor.

Encapsulates column geometry (offset gutter, hex area, ASCII area) and
the bidirectional mapping between viewport pixel coordinates and byte
offsets.  Keeps layout concerns out of the widget and painter.

Design pattern: **Value Object** — recalculated when font or
bytes-per-line changes, then shared read-only between widget and painter.
"""

from PySide6.QtCore import QPoint
from PySide6.QtGui import QFontMetrics

from .hex_data_buffer import HexDataBuffer


# Layout constants
DEFAULT_BYTES_PER_LINE = 16
MIN_BYTES_PER_LINE = 4
MAX_BYTES_PER_LINE = 64
OFFSET_CHARS = 10  # "00000000  "


class HexLayout:
    """Column geometry and pixel-to-offset mapping for the hex view."""

    def __init__(self):
        self.char_w: int = 0
        self.line_h: int = 0

        # Column positions (pixels)
        self.offset_width: int = 0
        self.hex_start: int = 0
        self.hex_col_width: int = 0
        self.ascii_start: int = 0
        self.ascii_width: int = 0
        self.total_width: int = 0

        self._bytes_per_line_hex: int = DEFAULT_BYTES_PER_LINE
        self._text_cols: int = 64

    @property
    def bytes_per_line_hex(self) -> int:
        return self._bytes_per_line_hex

    def set_bytes_per_line(self, n: int) -> bool:
        """Set hex-mode bytes-per-line, clamped. Returns True if changed."""
        n = max(MIN_BYTES_PER_LINE, min(int(n), MAX_BYTES_PER_LINE))
        if n == self._bytes_per_line_hex:
            return False
        self._bytes_per_line_hex = n
        return True

    @property
    def text_cols(self) -> int:
        return self._text_cols

    def bytes_per_line(self, text_mode: bool) -> int:
        return self._text_cols if text_mode else self._bytes_per_line_hex

    def update_metrics(self, fm: QFontMetrics):
        """Recalculate all column positions from the given font metrics."""
        self.char_w = fm.horizontalAdvance("0")
        self.line_h = fm.height() + 2

        bpl = self._bytes_per_line_hex
        mid_gaps = (bpl - 1) // 8

        self.offset_width = OFFSET_CHARS * self.char_w
        self.hex_start = self.offset_width + self.char_w
        self.hex_col_width = (3 * bpl + mid_gaps) * self.char_w
        self.ascii_start = self.hex_start + self.hex_col_width + self.char_w
        self.ascii_width = bpl * self.char_w
        self.total_width = self.ascii_start + self.ascii_width + self.char_w

    # ── Coordinate mapping ──────────────────────────────────────────

    def offset_from_point(self, pos: QPoint, scroll_value: int,
                          buffer: HexDataBuffer | None,
                          text_mode: bool, text_escape_mode: bool,
                          text_line_starts: list[int],
                          rebuild_lines_fn) -> int:
        """Map viewport (x, y) to byte offset, or -1."""
        if not buffer:
            return -1

        bpl = self.bytes_per_line(text_mode)
        line = scroll_value + pos.y() // self.line_h
        x = pos.x()

        if text_mode:
            return self._offset_from_text(
                x, line, bpl, buffer, text_escape_mode,
                text_line_starts, rebuild_lines_fn)

        return self._offset_from_hex(x, line, bpl, buffer)

    def _offset_from_hex(self, x: int, line: int, bpl: int,
                         buffer: HexDataBuffer) -> int:
        """Map pixel x within a hex-mode line to byte offset."""
        offset_base = line * bpl

        # Hex column
        if self.hex_start <= x < self.ascii_start - self.char_w // 2:
            rel_chars = (x - self.hex_start) / self.char_w
            group = int(rel_chars // 25)
            within = rel_chars - group * 25
            if within < 24:
                col = group * 8 + int(within // 3)
            else:
                col = group * 8 + 7
            col = max(0, min(col, bpl - 1))
            return min(offset_base + col, buffer.size() - 1)

        # ASCII column
        if self.ascii_start <= x < self.ascii_start + self.ascii_width:
            col = (x - self.ascii_start) // self.char_w
            col = max(0, min(col, bpl - 1))
            return min(offset_base + col, buffer.size() - 1)

        return -1

    def _offset_from_text(self, x: int, line: int, bpl: int,
                          buffer: HexDataBuffer,
                          escape_mode: bool,
                          text_line_starts: list[int],
                          rebuild_lines_fn) -> int:
        """Map pixel x within a text-mode line to byte offset."""
        text_start = self.offset_width + self.char_w
        if x < text_start:
            return -1

        col = max(0, int((x - text_start) // self.char_w))

        if escape_mode:
            offset_base = line * bpl
            col = min(col, bpl - 1)
            return min(offset_base + col, buffer.size() - 1)

        # Notepad mode
        if not text_line_starts:
            rebuild_lines_fn()
        starts = text_line_starts
        if not starts:
            return -1

        line_idx = max(0, min(line, len(starts) - 1))
        line_start = starts[line_idx]
        line_end = (starts[line_idx + 1]
                    if line_idx + 1 < len(starts) else buffer.size())

        content_end = line_end
        if content_end > line_start and buffer.read(content_end - 1, 1) == b"\n":
            content_end -= 1
        if content_end > line_start and buffer.read(content_end - 1, 1) == b"\r":
            content_end -= 1
        content_len = max(0, content_end - line_start)
        col = min(col, content_len)
        return min(line_start + col, buffer.size() - 1)

    def is_in_ascii_area(self, x: int) -> bool:
        """Return True if pixel x falls in the ASCII column."""
        return x >= self.ascii_start

    # ── Line calculations ───────────────────────────────────────────

    def total_lines(self, buffer_size: int, text_mode: bool,
                    text_line_count: int) -> int:
        if buffer_size == 0:
            return 0
        if text_mode:
            return text_line_count
        bpl = self._bytes_per_line_hex
        return (buffer_size + bpl - 1) // bpl

    def visible_lines(self, viewport_height: int) -> int:
        return max(1, viewport_height // self.line_h)

    def line_for_offset(self, offset: int, text_mode: bool,
                        text_escape_mode: bool,
                        byte_to_text_line_fn) -> int:
        """Return the row index that *offset* appears on."""
        if text_mode and not text_escape_mode:
            return byte_to_text_line_fn(offset)
        bpl = self.bytes_per_line(text_mode)
        return offset // bpl
