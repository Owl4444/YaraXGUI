# -*- coding: utf-8 -*-
"""Painting engine for the hex editor.

Uses the **Strategy** pattern: three concrete strategies
(HexModePainter, TextEscapePainter, TextNotepadPainter) share a common
base that renders the offset gutter, marker triangles, separator lines,
and highlight overlays.  Each strategy only overrides the per-line
content rendering, eliminating the massive duplication that previously
existed across _paint_hex_mode / _paint_text_escape_mode /
_paint_text_notepad_mode.

Design pattern: **Template Method** — ``paint_line()`` defines the
skeleton (gutter -> separator -> content) while subclasses provide
``_paint_line_content()``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from PySide6.QtCore import Qt, QRect, QPoint
from PySide6.QtGui import QPainter, QColor, QPen, QPolygon

from .hex_data_buffer import HexDataBuffer
from .hex_layout import HexLayout
from .selection_model import SelectionModel


class PaintContext:
    """Read-only snapshot of everything a painter needs for one frame.

    Gathered once per paintEvent so strategies don't reach back into the
    widget for mutable state mid-render.
    """

    __slots__ = (
        "buffer", "layout", "selection", "font",
        "first_line", "visible_lines", "viewport_width",
        "sel_min", "sel_max",
        # colours
        "bg", "offset_bg", "offset_text", "hex_text",
        "ascii_text", "ascii_nonprint", "cursor_bg",
        "selection_bg", "separator", "pattern_region_color",
        # edit tracking
        "modified_offsets", "edited_hex_text", "edited_ascii_text",
        # gutter
        "gutter_mode",  # "offset" | "line"
        # binary diff
        "diff_offsets", "diff_bg",
    )

    def __init__(self, *, buffer, layout, selection, font,
                 first_line, visible_lines, viewport_width,
                 bg, offset_bg, offset_text, hex_text,
                 ascii_text, ascii_nonprint, cursor_bg,
                 selection_bg, separator, pattern_region_color,
                 modified_offsets=None,
                 edited_hex_text=None, edited_ascii_text=None,
                 gutter_mode="offset",
                 diff_offsets=None, diff_bg=None):
        self.buffer: HexDataBuffer = buffer
        self.layout: HexLayout = layout
        self.selection: SelectionModel = selection
        self.font = font
        self.first_line: int = first_line
        self.visible_lines: int = visible_lines
        self.viewport_width: int = viewport_width
        self.sel_min, self.sel_max = selection.ordered_selection()
        self.bg: QColor = bg
        self.offset_bg: QColor = offset_bg
        self.offset_text: QColor = offset_text
        self.hex_text: QColor = hex_text
        self.ascii_text: QColor = ascii_text
        self.ascii_nonprint: QColor = ascii_nonprint
        self.cursor_bg: QColor = cursor_bg
        self.selection_bg: QColor = selection_bg
        self.separator: QColor = separator
        self.pattern_region_color: QColor = pattern_region_color
        # Edit tracking — set of modified byte offsets
        self.modified_offsets: set[int] = modified_offsets or set()
        self.edited_hex_text: QColor = edited_hex_text or QColor("#e05050")
        self.edited_ascii_text: QColor = edited_ascii_text or QColor("#e05050")
        self.gutter_mode: str = gutter_mode
        # Binary diff highlighting (yellow background distinct from edited red)
        self.diff_offsets: set[int] = diff_offsets or set()
        self.diff_bg: QColor = diff_bg or QColor(255, 220, 80, 110)


# ── Shared rendering helpers ───────────────────────────────────────


def _paint_offset_gutter(painter: QPainter, ctx: PaintContext,
                         y: int, offset: int, line_idx: int = 0):
    """Render the offset column — hex offset or line number."""
    L = ctx.layout
    painter.fillRect(QRect(0, y, L.offset_width, L.line_h), ctx.offset_bg)
    painter.setPen(ctx.offset_text)
    if ctx.gutter_mode == "line":
        label = str(line_idx + 1)  # 1-based line numbers
    else:
        label = f"{offset:08X}"
    painter.drawText(
        QRect(0, y, L.offset_width - L.char_w, L.line_h),
        Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
        label,
    )


def _paint_marker_triangles(painter: QPainter, ctx: PaintContext,
                            y: int, line_start: int, line_end: int):
    """Draw green (start) and red (end) marker triangles in the gutter."""
    L = ctx.layout
    tri_x = 2
    tri_size = L.line_h // 3
    tri_cy = y + L.line_h // 2
    sel = ctx.selection

    for marker_off, color in (
        (sel.marker_start, QColor("#22bb45")),
        (sel.marker_end, QColor("#dd3333")),
    ):
        if marker_off >= 0 and line_start <= marker_off <= line_end:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(color)
            painter.drawPolygon(QPolygon([
                QPoint(tri_x, tri_cy - tri_size),
                QPoint(tri_x + tri_size, tri_cy),
                QPoint(tri_x, tri_cy + tri_size),
            ]))


def _paint_separator(painter: QPainter, ctx: PaintContext,
                     x: int, y: int):
    """Draw a thin vertical separator line."""
    painter.setPen(QPen(ctx.separator, 1))
    painter.drawLine(x, y, x, y + ctx.layout.line_h)


def _paint_cell_highlights(painter: QPainter, ctx: PaintContext,
                           rect: QRect, byte_offset: int,
                           is_cursor_area: bool,
                           check_pattern_regions: bool = True):
    """Apply highlight layers for a single byte cell.

    Layer order (bottom to top):
    1. Pattern region overlay (orange) — if check_pattern_regions
    2. Selection highlight (semi-transparent blue)
    3. Cursor highlight (solid blue)

    Returns True if the cursor highlight was applied (caller should
    use white text).
    """
    if check_pattern_regions:
        for pr_start, pr_end in ctx.selection.pattern_regions:
            if pr_start <= byte_offset <= pr_end:
                painter.fillRect(rect, ctx.pattern_region_color)
                break

    # Diff highlight (yellow tint) — above pattern regions, below selection
    if byte_offset in ctx.diff_offsets:
        painter.fillRect(rect, ctx.diff_bg)

    if ctx.sel_min <= byte_offset <= ctx.sel_max:
        painter.fillRect(rect, ctx.selection_bg)

    if byte_offset == ctx.selection.cursor and is_cursor_area:
        painter.fillRect(rect, ctx.cursor_bg)
        return True

    return False


# ── Base strategy ──────────────────────────────────────────────────


class BasePaintStrategy(ABC):
    """Template method for painting hex editor lines."""

    def paint(self, painter: QPainter, ctx: PaintContext):
        """Full-frame paint: background, then each visible line."""
        painter.setFont(ctx.font)
        painter.fillRect(
            QRect(0, 0, ctx.viewport_width,
                  (ctx.visible_lines + 1) * ctx.layout.line_h),
            ctx.bg,
        )

        for i in range(ctx.visible_lines + 1):
            line_idx = ctx.first_line + i
            line_info = self._line_info(line_idx, ctx)
            if line_info is None:
                break

            offset, data, data_len = line_info
            y = i * ctx.layout.line_h

            _paint_offset_gutter(painter, ctx, y, offset, line_idx)
            _paint_marker_triangles(painter, ctx, y, offset,
                                    offset + max(data_len - 1, 0))
            _paint_separator(painter, ctx, ctx.layout.offset_width, y)
            self._paint_line_content(painter, ctx, y, offset, data, data_len)

    @abstractmethod
    def _line_info(self, line_idx: int, ctx: PaintContext):
        """Return (offset, data_bytes, data_len) or None if past EOF."""

    @abstractmethod
    def _paint_line_content(self, painter: QPainter, ctx: PaintContext,
                            y: int, offset: int,
                            data: bytes, data_len: int):
        """Render the line's byte content (hex+ASCII, or text chars)."""


# ── Hex mode strategy ──────────────────────────────────────────────


class HexModePainter(BasePaintStrategy):
    """Renders the classic offset | hex bytes | ASCII columns."""

    def _line_info(self, line_idx, ctx):
        bpl = ctx.layout.bytes_per_line_hex
        offset = line_idx * bpl
        if offset >= ctx.buffer.size():
            return None
        data = ctx.buffer.read(offset, bpl)
        return (offset, data, len(data))

    def _paint_line_content(self, painter, ctx, y, offset, data, data_len):
        L = ctx.layout
        sel = ctx.selection
        modified = ctx.modified_offsets

        # Hex bytes
        for j in range(data_len):
            byte_offset = offset + j
            x = L.hex_start + j * 3 * L.char_w + (j // 8) * L.char_w
            byte_rect = QRect(x, y, 2 * L.char_w, L.line_h)

            is_cursor = _paint_cell_highlights(
                painter, ctx, byte_rect, byte_offset,
                is_cursor_area=not sel.focus_ascii)

            if is_cursor:
                painter.setPen(QColor("#ffffff"))
            elif byte_offset in modified:
                painter.setPen(ctx.edited_hex_text)
            else:
                painter.setPen(ctx.hex_text)
            painter.drawText(byte_rect, Qt.AlignmentFlag.AlignCenter,
                             f"{data[j]:02X}")

        # Separator before ASCII
        sep_x = L.ascii_start - L.char_w // 2
        _paint_separator(painter, ctx, sep_x, y)

        # ASCII column
        for j in range(data_len):
            byte_offset = offset + j
            ch = data[j]
            x = L.ascii_start + j * L.char_w
            char_rect = QRect(x, y, L.char_w, L.line_h)

            is_cursor = _paint_cell_highlights(
                painter, ctx, char_rect, byte_offset,
                is_cursor_area=sel.focus_ascii)

            if is_cursor:
                painter.setPen(QColor("#ffffff"))
            elif byte_offset in modified:
                painter.setPen(ctx.edited_ascii_text)
            elif 32 <= ch <= 126:
                painter.setPen(ctx.ascii_text)
            else:
                painter.setPen(ctx.ascii_nonprint)

            display = chr(ch) if 32 <= ch <= 126 else "."
            painter.drawText(char_rect, Qt.AlignmentFlag.AlignCenter, display)


# ── Text escape mode strategy ──────────────────────────────────────


class TextEscapePainter(BasePaintStrategy):
    """Fixed 64-byte grid with dots for non-printable characters."""

    def _line_info(self, line_idx, ctx):
        bpl = ctx.layout.text_cols
        offset = line_idx * bpl
        if offset >= ctx.buffer.size():
            return None
        data = ctx.buffer.read(offset, bpl)
        return (offset, data, len(data))

    def _paint_line_content(self, painter, ctx, y, offset, data, data_len):
        L = ctx.layout
        text_start = L.offset_width + L.char_w

        for j in range(data_len):
            byte_offset = offset + j
            ch = data[j]
            x = text_start + j * L.char_w
            char_rect = QRect(x, y, L.char_w, L.line_h)

            is_cursor = _paint_cell_highlights(
                painter, ctx, char_rect, byte_offset,
                is_cursor_area=True, check_pattern_regions=False)

            if is_cursor:
                painter.setPen(QColor("#ffffff"))
            elif 32 <= ch <= 126:
                painter.setPen(ctx.ascii_text)
            else:
                painter.setPen(ctx.ascii_nonprint)

            display = chr(ch) if 32 <= ch <= 126 else "\u00b7"
            painter.drawText(char_rect, Qt.AlignmentFlag.AlignCenter, display)


# ── Text notepad mode strategy ─────────────────────────────────────


class TextNotepadPainter(BasePaintStrategy):
    """Honors real \\n line breaks with variable-width lines."""

    def __init__(self, text_line_starts: list[int]):
        self._starts = text_line_starts

    def _line_info(self, line_idx, ctx):
        starts = self._starts
        if line_idx >= len(starts):
            return None
        size = ctx.buffer.size()
        line_start = starts[line_idx]
        line_end = starts[line_idx + 1] if line_idx + 1 < len(starts) else size

        content_end = line_end
        if content_end > line_start and ctx.buffer.read(content_end - 1, 1) == b"\n":
            content_end -= 1
        if content_end > line_start and ctx.buffer.read(content_end - 1, 1) == b"\r":
            content_end -= 1

        L = ctx.layout
        text_start = L.offset_width + L.char_w
        max_visual_cols = max(1, (ctx.viewport_width - text_start) // L.char_w)
        content_len = content_end - line_start
        read_len = min(content_len, max_visual_cols + 1)
        data = ctx.buffer.read(line_start, read_len) if read_len > 0 else b""
        return (line_start, data, len(data))

    def _paint_line_content(self, painter, ctx, y, offset, data, data_len):
        L = ctx.layout
        text_start = L.offset_width + L.char_w
        sel = ctx.selection

        for j in range(data_len):
            byte_offset = offset + j
            ch = data[j]
            x = text_start + j * L.char_w
            char_rect = QRect(x, y, L.char_w, L.line_h)

            is_cursor = _paint_cell_highlights(
                painter, ctx, char_rect, byte_offset,
                is_cursor_area=True, check_pattern_regions=False)

            if is_cursor:
                painter.setPen(QColor("#ffffff"))
            elif 32 <= ch <= 126:
                painter.setPen(ctx.ascii_text)
            else:
                painter.setPen(ctx.ascii_nonprint)

            if 32 <= ch <= 126:
                display = chr(ch)
            elif ch == 0x09:
                display = " "
            else:
                display = "\u00b7"
            painter.drawText(char_rect, Qt.AlignmentFlag.AlignCenter, display)

        # Cursor at end-of-line (pointing at \n terminator)
        # Compute the full content length for this line
        starts = self._starts
        # Find line index for this offset
        line_idx = -1
        for idx, s in enumerate(starts):
            if s == offset:
                line_idx = idx
                break
        if line_idx >= 0:
            size = ctx.buffer.size()
            line_end = starts[line_idx + 1] if line_idx + 1 < len(starts) else size
            content_end = line_end
            if content_end > offset and ctx.buffer.read(content_end - 1, 1) == b"\n":
                content_end -= 1
            if content_end > offset and ctx.buffer.read(content_end - 1, 1) == b"\r":
                content_end -= 1
            content_len = max(0, content_end - offset)
            if sel.cursor == content_end and sel.cursor < line_end:
                cx = text_start + content_len * L.char_w
                cursor_rect = QRect(cx, y, L.char_w, L.line_h)
                painter.fillRect(cursor_rect, ctx.cursor_bg)
