# -*- coding: utf-8 -*-
"""Core hex view widget using QAbstractScrollArea with custom painting."""

from PySide6.QtCore import Qt, Signal, QRect, QPoint
from PySide6.QtGui import (QFont, QFontMetrics, QPainter, QColor, QPen,
                           QKeyEvent, QMouseEvent, QWheelEvent, QPalette,
                           QKeySequence, QAction, QPolygon)
from PySide6.QtWidgets import QAbstractScrollArea, QApplication, QMenu

from .hex_data_buffer import HexDataBuffer


# Layout constants
DEFAULT_BYTES_PER_LINE = 16
MIN_BYTES_PER_LINE = 4
MAX_BYTES_PER_LINE = 64
OFFSET_CHARS = 10  # "00000000: "


class HexWidget(QAbstractScrollArea):
    """Custom hex view widget rendering offset | hex | ASCII columns."""

    cursor_moved = Signal(int)           # emits cursor offset
    selection_changed = Signal(int, int) # emits start, length
    yara_pattern_requested = Signal(str) # emits "$hex_N = { ... }"
    pattern_regions_changed = Signal(int) # emits region count
    disassemble_requested = Signal(bytes, int)  # selected_bytes, base_offset
    transform_requested = Signal()       # emits when user picks "Apply Transform…"
    bytes_per_line_changed = Signal(int) # emits new bytes-per-line (hex mode only)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._buffer: HexDataBuffer | None = None
        self._cursor_offset = 0
        self._selection_start = -1
        self._selection_end = -1
        self._selecting = False  # mouse drag in progress
        self._focus_ascii = False  # Tab toggles hex/ascii focus
        self._text_mode = False   # False=hex view, True=text view

        # Hex-mode layout (configurable)
        self._bytes_per_line_hex = DEFAULT_BYTES_PER_LINE

        # Text-mode layout
        self._text_cols = 64  # characters per line in text mode

        # Persistent selection markers
        self._marker_start: int = -1
        self._marker_end: int = -1

        # Auto-incrementing YARA pattern counter
        self._yara_counter: int = 0

        # Wildcard pattern builder regions
        self._pattern_regions: list[tuple[int, int]] = []  # (start, end) inclusive
        self._pattern_region_color = QColor(255, 165, 0, 100)  # orange overlay

        # Theme colours (defaults — overridden by set_theme)
        self._offset_bg = QColor("#f0f0f0")
        self._offset_text = QColor("#666666")
        self._hex_text = QColor("#000000")
        self._ascii_text = QColor("#0066cc")
        self._ascii_nonprint = QColor("#cccccc")
        self._cursor_bg = QColor("#3399ff")
        self._separator = QColor("#cccccc")
        self._bg = QColor("#ffffff")
        self._selection_bg = QColor(51, 153, 255, 160)

        # Font — must be truly fixed-pitch. Cascadia Code has ligatures
        # that collapse pairs like "XX" in rendering, so we prefer
        # Cascadia Mono / Consolas / Courier New with styleHint Monospace
        # and setFixedPitch(True) as a hard guarantee.
        self._font = QFont()
        self._font.setFamilies([
            "Cascadia Mono",
            "Consolas",
            "Courier New",
            "DejaVu Sans Mono",
            "monospace",
        ])
        self._font.setPointSize(10)
        self._font.setStyleHint(QFont.StyleHint.Monospace,
                                QFont.StyleStrategy.PreferDefault)
        self._font.setFixedPitch(True)
        self._font.setKerning(False)
        self.setFont(self._font)
        self._update_metrics()

        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

    # ── Metrics ─────────────────────────────────────────────────────

    def _update_metrics(self):
        fm = QFontMetrics(self.font())
        # Font is guaranteed fixed-pitch (Cascadia Mono / Consolas with
        # setFixedPitch) so every glyph has the same advance — use "0".
        self._char_w = fm.horizontalAdvance("0")
        self._line_h = fm.height() + 2  # small padding

        bpl = self._bytes_per_line_hex
        # Mid gap only if there's a "byte 8" split worth rendering
        mid_gap = 1 if bpl > 8 else 0

        # Column positions (in chars then converted to px)
        # Offset column: "00000000  " = 10 chars
        self._offset_width = OFFSET_CHARS * self._char_w
        # Hex column: "XX " * bpl + extra gap at byte 8
        self._hex_start = self._offset_width + self._char_w
        self._hex_col_width = (3 * bpl + mid_gap) * self._char_w
        # ASCII column
        self._ascii_start = self._hex_start + self._hex_col_width + self._char_w
        self._ascii_width = bpl * self._char_w
        self._total_width = self._ascii_start + self._ascii_width + self._char_w

    def setFont(self, font):
        super().setFont(font)
        self._font = font
        self._update_metrics()
        self.viewport().update()

    # ── Data binding ────────────────────────────────────────────────

    def set_buffer(self, buf: HexDataBuffer):
        self._buffer = buf
        self._cursor_offset = 0
        self._selection_start = -1
        self._selection_end = -1
        self._update_scrollbar()
        self.viewport().update()
        self.cursor_moved.emit(0)

    def _bytes_per_line(self) -> int:
        return self._text_cols if self._text_mode else self._bytes_per_line_hex

    def bytes_per_line(self) -> int:
        """Public accessor for the current hex-mode bytes-per-line."""
        return self._bytes_per_line_hex

    def set_bytes_per_line(self, n: int):
        """Change hex-mode bytes-per-line; clamps to MIN..MAX."""
        n = max(MIN_BYTES_PER_LINE, min(int(n), MAX_BYTES_PER_LINE))
        if n == self._bytes_per_line_hex:
            return
        # Preserve approximate cursor position (stay at same byte).
        self._bytes_per_line_hex = n
        self._update_metrics()
        self._update_scrollbar()
        # Snap cursor so _ensure_visible uses the new bpl correctly
        if self._buffer is not None:
            self._ensure_visible(self._cursor_offset)
        self.viewport().update()
        self.bytes_per_line_changed.emit(n)

    def _total_lines(self) -> int:
        if not self._buffer:
            return 0
        bpl = self._bytes_per_line()
        return (self._buffer.size() + bpl - 1) // bpl

    def set_text_mode(self, enabled: bool):
        """Toggle between hex view and text view."""
        if self._text_mode == enabled:
            return
        self._text_mode = enabled
        self._update_scrollbar()
        self.viewport().update()

    def _visible_lines(self) -> int:
        return max(1, self.viewport().height() // self._line_h)

    def _update_scrollbar(self):
        total = self._total_lines()
        visible = self._visible_lines()
        self.verticalScrollBar().setRange(0, max(0, total - visible))
        self.verticalScrollBar().setPageStep(visible)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_scrollbar()

    # ── Theme ───────────────────────────────────────────────────────

    def set_theme(self, colors):
        """Apply theme colours from ThemeColors (or dict with hex_ keys)."""
        def _c(attr, fallback):
            val = getattr(colors, attr, None) if hasattr(colors, attr) else colors.get(attr)
            return QColor(val) if val else fallback

        if hasattr(colors, "hex_offset_bg"):
            self._offset_bg = _c("hex_offset_bg", self._offset_bg)
            self._offset_text = _c("hex_offset_text", self._offset_text)
            self._hex_text = _c("hex_byte_text", self._hex_text)
            self._ascii_text = _c("hex_ascii_text", self._ascii_text)
            self._ascii_nonprint = _c("hex_ascii_nonprint", self._ascii_nonprint)
            self._cursor_bg = _c("hex_cursor_bg", self._cursor_bg)
            self._separator = _c("hex_separator", self._separator)
        # Also pick up generic background from theme
        bg = getattr(colors, "editor_background", None)
        if bg:
            self._bg = QColor(bg)
        sel = getattr(colors, "selection_background", None)
        if sel:
            c = QColor(sel)
            c.setAlpha(160)
            self._selection_bg = c

        # Make scrollbar clearly visible regardless of theme — use the
        # shared contrast helper so it always pops against the background.
        try:
            from themes import ensure_scrollbar_contrast
        except ImportError:
            ensure_scrollbar_contrast = None
        sb_bg = getattr(colors, "scrollbar_background", None) or self._bg.name()
        raw_handle = getattr(colors, "scrollbar_handle", None) or "#888888"
        raw_hover = getattr(colors, "scrollbar_handle_hover", None) or "#aaaaaa"
        if ensure_scrollbar_contrast:
            handle, handle_hover = ensure_scrollbar_contrast(sb_bg, raw_handle, raw_hover)
        else:
            handle, handle_hover = raw_handle, raw_hover
        self.setStyleSheet(f"""
            QScrollBar:vertical {{
                background: {sb_bg}; width: 14px; border: none; margin: 0px;
            }}
            QScrollBar:horizontal {{
                background: {sb_bg}; height: 14px; border: none; margin: 0px;
            }}
            QScrollBar::handle:vertical {{
                background: {handle}; min-height: 28px; border-radius: 4px;
                margin: 2px 3px 2px 3px;
            }}
            QScrollBar::handle:horizontal {{
                background: {handle}; min-width: 28px; border-radius: 4px;
                margin: 3px 2px 3px 2px;
            }}
            QScrollBar::handle:vertical:hover,
            QScrollBar::handle:horizontal:hover {{
                background: {handle_hover};
            }}
            QScrollBar::add-line, QScrollBar::sub-line {{
                width: 0px; height: 0px; background: none; border: none;
            }}
            QScrollBar::add-page, QScrollBar::sub-page {{
                background: none;
            }}
        """)

        self.viewport().update()

    # ── Painting ────────────────────────────────────────────────────

    def paintEvent(self, event):
        if not self._buffer or self._buffer.size() == 0:
            painter = QPainter(self.viewport())
            painter.fillRect(self.viewport().rect(), self._bg)
            painter.setPen(self._offset_text)
            painter.drawText(self.viewport().rect(), Qt.AlignmentFlag.AlignCenter,
                             "No file loaded — use File > Open or drag a file")
            painter.end()
            return

        if self._text_mode:
            self._paint_text_mode(event)
        else:
            self._paint_hex_mode(event)

    def _paint_hex_mode(self, event):
        painter = QPainter(self.viewport())
        painter.setFont(self._font)
        painter.fillRect(self.viewport().rect(), self._bg)

        bpl = self._bytes_per_line_hex
        mid_split = 8 if bpl > 8 else bpl  # where the mid-gap sits

        first_line = self.verticalScrollBar().value()
        visible = self._visible_lines() + 1

        sel_min, sel_max = self._ordered_selection()

        for i in range(visible):
            line_idx = first_line + i
            offset = line_idx * bpl
            if offset >= self._buffer.size():
                break

            y = i * self._line_h
            data = self._buffer.read(offset, bpl)
            data_len = len(data)

            # Offset column background
            painter.fillRect(QRect(0, y, self._offset_width, self._line_h), self._offset_bg)
            painter.setPen(self._offset_text)
            painter.drawText(
                QRect(0, y, self._offset_width - self._char_w, self._line_h),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                f"{offset:08X}"
            )

            # Draw marker triangles in gutter
            line_end = offset + data_len - 1
            tri_x = 2
            tri_size = self._line_h // 3
            tri_cy = y + self._line_h // 2
            if self._marker_start >= 0 and offset <= self._marker_start <= line_end:
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor("#22bb45"))  # green
                tri = QPolygon([
                    QPoint(tri_x, tri_cy - tri_size),
                    QPoint(tri_x + tri_size, tri_cy),
                    QPoint(tri_x, tri_cy + tri_size),
                ])
                painter.drawPolygon(tri)
            if self._marker_end >= 0 and offset <= self._marker_end <= line_end:
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor("#dd3333"))  # red
                tri = QPolygon([
                    QPoint(tri_x, tri_cy - tri_size),
                    QPoint(tri_x + tri_size, tri_cy),
                    QPoint(tri_x, tri_cy + tri_size),
                ])
                painter.drawPolygon(tri)

            # Separator line after offset
            painter.setPen(QPen(self._separator, 1))
            painter.drawLine(self._offset_width, y, self._offset_width, y + self._line_h)

            # Hex bytes
            for j in range(data_len):
                byte_offset = offset + j
                x = self._hex_start + j * 3 * self._char_w
                # Extra gap at the mid-split (only when bpl > 8)
                if bpl > 8 and j >= mid_split:
                    x += self._char_w

                byte_rect = QRect(x, y, 2 * self._char_w, self._line_h)

                # Pattern region overlay (orange)
                for pr_start, pr_end in self._pattern_regions:
                    if pr_start <= byte_offset <= pr_end:
                        painter.fillRect(byte_rect, self._pattern_region_color)
                        break

                # Selection / cursor highlight
                if sel_min <= byte_offset <= sel_max:
                    painter.fillRect(byte_rect, self._selection_bg)
                if byte_offset == self._cursor_offset and not self._focus_ascii:
                    painter.fillRect(byte_rect, self._cursor_bg)
                    painter.setPen(QColor("#ffffff"))
                else:
                    painter.setPen(self._hex_text)

                painter.drawText(byte_rect, Qt.AlignmentFlag.AlignCenter, f"{data[j]:02X}")

            # Separator before ASCII
            sep_x = self._ascii_start - self._char_w // 2
            painter.setPen(QPen(self._separator, 1))
            painter.drawLine(sep_x, y, sep_x, y + self._line_h)

            # ASCII column
            for j in range(data_len):
                byte_offset = offset + j
                ch = data[j]
                x = self._ascii_start + j * self._char_w
                char_rect = QRect(x, y, self._char_w, self._line_h)

                # Pattern region overlay (orange)
                for pr_start, pr_end in self._pattern_regions:
                    if pr_start <= byte_offset <= pr_end:
                        painter.fillRect(char_rect, self._pattern_region_color)
                        break

                if sel_min <= byte_offset <= sel_max:
                    painter.fillRect(char_rect, self._selection_bg)
                if byte_offset == self._cursor_offset and self._focus_ascii:
                    painter.fillRect(char_rect, self._cursor_bg)
                    painter.setPen(QColor("#ffffff"))
                elif 32 <= ch <= 126:
                    painter.setPen(self._ascii_text)
                else:
                    painter.setPen(self._ascii_nonprint)

                display = chr(ch) if 32 <= ch <= 126 else "."
                painter.drawText(char_rect, Qt.AlignmentFlag.AlignCenter, display)

        painter.end()

    def _paint_text_mode(self, event):
        painter = QPainter(self.viewport())
        painter.setFont(self._font)
        painter.fillRect(self.viewport().rect(), self._bg)

        first_line = self.verticalScrollBar().value()
        visible = self._visible_lines() + 1
        bpl = self._text_cols
        text_start = self._offset_width + self._char_w

        sel_min, sel_max = self._ordered_selection()

        for i in range(visible):
            line_idx = first_line + i
            offset = line_idx * bpl
            if offset >= self._buffer.size():
                break

            y = i * self._line_h
            data = self._buffer.read(offset, bpl)
            data_len = len(data)

            # Offset gutter
            painter.fillRect(QRect(0, y, self._offset_width, self._line_h), self._offset_bg)
            painter.setPen(self._offset_text)
            painter.drawText(
                QRect(0, y, self._offset_width - self._char_w, self._line_h),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                f"{offset:08X}"
            )

            # Marker triangles
            line_end = offset + data_len - 1
            tri_x = 2
            tri_size = self._line_h // 3
            tri_cy = y + self._line_h // 2
            if self._marker_start >= 0 and offset <= self._marker_start <= line_end:
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor("#22bb45"))
                painter.drawPolygon(QPolygon([
                    QPoint(tri_x, tri_cy - tri_size),
                    QPoint(tri_x + tri_size, tri_cy),
                    QPoint(tri_x, tri_cy + tri_size),
                ]))
            if self._marker_end >= 0 and offset <= self._marker_end <= line_end:
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor("#dd3333"))
                painter.drawPolygon(QPolygon([
                    QPoint(tri_x, tri_cy - tri_size),
                    QPoint(tri_x + tri_size, tri_cy),
                    QPoint(tri_x, tri_cy + tri_size),
                ]))

            # Separator
            painter.setPen(QPen(self._separator, 1))
            painter.drawLine(self._offset_width, y, self._offset_width, y + self._line_h)

            # Text characters
            for j in range(data_len):
                byte_offset = offset + j
                ch = data[j]
                x = text_start + j * self._char_w
                char_rect = QRect(x, y, self._char_w, self._line_h)

                # Selection highlight
                if sel_min <= byte_offset <= sel_max:
                    painter.fillRect(char_rect, self._selection_bg)
                # Cursor highlight
                if byte_offset == self._cursor_offset:
                    painter.fillRect(char_rect, self._cursor_bg)
                    painter.setPen(QColor("#ffffff"))
                elif 32 <= ch <= 126:
                    painter.setPen(self._ascii_text)
                else:
                    painter.setPen(self._ascii_nonprint)

                display = chr(ch) if 32 <= ch <= 126 else "\u00b7"
                painter.drawText(char_rect, Qt.AlignmentFlag.AlignCenter, display)

        painter.end()

    # ── Selection helpers ───────────────────────────────────────────

    def _ordered_selection(self):
        if self._selection_start < 0 or self._selection_end < 0:
            return (-1, -1)
        return (min(self._selection_start, self._selection_end),
                max(self._selection_start, self._selection_end))

    def has_selection(self) -> bool:
        return self._selection_start >= 0 and self._selection_end >= 0

    def selected_bytes(self) -> bytes:
        if not self.has_selection() or not self._buffer:
            return b""
        lo, hi = self._ordered_selection()
        return self._buffer.read(lo, hi - lo + 1)

    # ── Coordinate mapping ──────────────────────────────────────────

    def _offset_from_point(self, pos: QPoint) -> int:
        """Map viewport (x, y) to byte offset, or -1."""
        if not self._buffer:
            return -1

        bpl = self._bytes_per_line()
        line = self.verticalScrollBar().value() + pos.y() // self._line_h
        offset_base = line * bpl
        x = pos.x()

        if self._text_mode:
            # Text mode: single text column after offset gutter
            text_start = self._offset_width + self._char_w
            if x >= text_start:
                col = int((x - text_start) // self._char_w)
                col = max(0, min(col, bpl - 1))
                off = offset_base + col
                return min(off, self._buffer.size() - 1)
            return -1

        # Hex mode: check hex column
        if self._hex_start <= x < self._ascii_start - self._char_w // 2:
            rel = x - self._hex_start
            # Account for mid gap (only present when bpl > 8)
            col = int(rel // (3 * self._char_w))
            if bpl > 8 and col >= 8:
                # Adjust for mid-gap
                rel2 = x - self._hex_start - self._char_w
                col = int(rel2 // (3 * self._char_w))
                if col < 8:
                    col = 8
            col = max(0, min(col, bpl - 1))
            off = offset_base + col
            return min(off, self._buffer.size() - 1)

        # Check ASCII column
        if self._ascii_start <= x < self._ascii_start + self._ascii_width:
            col = (x - self._ascii_start) // self._char_w
            col = max(0, min(col, bpl - 1))
            off = offset_base + col
            return min(off, self._buffer.size() - 1)

        return -1

    # ── Mouse events ────────────────────────────────────────────────

    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.MouseButton.LeftButton:
            off = self._offset_from_point(event.position().toPoint())
            if off >= 0:
                # Determine if click is in ASCII area
                if self._text_mode:
                    self._focus_ascii = True
                else:
                    x = event.position().toPoint().x()
                    self._focus_ascii = x >= self._ascii_start

                if event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                    self._selection_end = off
                else:
                    self._cursor_offset = off
                    self._selection_start = off
                    self._selection_end = off
                    self._selecting = True
                self.cursor_moved.emit(self._cursor_offset)
                self.viewport().update()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent):
        if self._selecting:
            off = self._offset_from_point(event.position().toPoint())
            if off >= 0:
                self._selection_end = off
                self._cursor_offset = off
                self.cursor_moved.emit(off)
                self.viewport().update()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent):
        if event.button() == Qt.MouseButton.LeftButton:
            self._selecting = False
            if self._selection_start == self._selection_end:
                self._selection_start = -1
                self._selection_end = -1
                # Emit a zero-length selection so observers (e.g. the
                # data inspector) know to clear any prior range.
                self.selection_changed.emit(self._cursor_offset, 0)
            else:
                lo, hi = self._ordered_selection()
                self.selection_changed.emit(lo, hi - lo + 1)
        super().mouseReleaseEvent(event)

    # ── Keyboard events ─────────────────────────────────────────────

    def keyPressEvent(self, event: QKeyEvent):
        if not self._buffer or self._buffer.size() == 0:
            super().keyPressEvent(event)
            return

        max_off = self._buffer.size() - 1
        shift = bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier)
        ctrl = bool(event.modifiers() & Qt.KeyboardModifier.ControlModifier)

        key = event.key()
        new_off = self._cursor_offset

        bpl = self._bytes_per_line()

        if key == Qt.Key.Key_Right:
            new_off = min(self._cursor_offset + 1, max_off)
        elif key == Qt.Key.Key_Left:
            new_off = max(self._cursor_offset - 1, 0)
        elif key == Qt.Key.Key_Down:
            new_off = min(self._cursor_offset + bpl, max_off)
        elif key == Qt.Key.Key_Up:
            new_off = max(self._cursor_offset - bpl, 0)
        elif key == Qt.Key.Key_PageDown:
            new_off = min(self._cursor_offset + self._visible_lines() * bpl, max_off)
        elif key == Qt.Key.Key_PageUp:
            new_off = max(self._cursor_offset - self._visible_lines() * bpl, 0)
        elif key == Qt.Key.Key_Home:
            if ctrl:
                new_off = 0
            else:
                new_off = (self._cursor_offset // bpl) * bpl
        elif key == Qt.Key.Key_End:
            if ctrl:
                new_off = max_off
            else:
                new_off = min((self._cursor_offset // bpl) * bpl + bpl - 1, max_off)
        elif key == Qt.Key.Key_Tab:
            self._focus_ascii = not self._focus_ascii
            self.viewport().update()
            return
        elif key == Qt.Key.Key_C and ctrl:
            self._copy_selection()
            return
        elif key == Qt.Key.Key_Y and ctrl and shift:
            self.send_to_yara_editor()
            return
        elif key == Qt.Key.Key_Y and ctrl:
            self.copy_as_yara_hex()
            return
        else:
            super().keyPressEvent(event)
            return

        # Update selection
        had_selection = self.has_selection()
        if shift:
            if self._selection_start < 0:
                self._selection_start = self._cursor_offset
            self._selection_end = new_off
        else:
            self._selection_start = -1
            self._selection_end = -1

        self._cursor_offset = new_off
        self._ensure_visible(new_off)
        self.cursor_moved.emit(new_off)

        # Keep observers (inspector, etc.) in sync with selection state.
        if shift and self.has_selection():
            lo, hi = self._ordered_selection()
            self.selection_changed.emit(lo, hi - lo + 1)
        elif had_selection:
            self.selection_changed.emit(new_off, 0)

        self.viewport().update()

    def _copy_selection(self):
        """Copy selected bytes (or cursor byte) to clipboard as hex or ASCII."""
        data = self._get_active_bytes()
        if not data:
            return
        if self._focus_ascii:
            text = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
        else:
            text = " ".join(f"{b:02X}" for b in data)
        QApplication.clipboard().setText(text)

    # ── Active bytes (unified source for all copy ops) ───────────

    def _get_active_bytes(self) -> bytes:
        """Return bytes from: markers range > drag selection > cursor byte."""
        if not self._buffer:
            return b""
        if self._marker_start >= 0 and self._marker_end >= 0:
            lo = min(self._marker_start, self._marker_end)
            hi = max(self._marker_start, self._marker_end)
            return self._buffer.read(lo, hi - lo + 1)
        if self.has_selection():
            return self.selected_bytes()
        return self._buffer.read(self._cursor_offset, 1)

    # ── Copy format methods ──────────────────────────────────────

    def copy_as_hex(self):
        """Copy as space-separated hex: 4D 5A 90 00"""
        data = self._get_active_bytes()
        if data:
            QApplication.clipboard().setText(" ".join(f"{b:02X}" for b in data))

    def copy_as_yara_hex(self):
        """Copy as YARA hex string: { 4D 5A 90 00 }"""
        data = self._get_active_bytes()
        if data:
            QApplication.clipboard().setText("{ " + " ".join(f"{b:02X}" for b in data) + " }")

    def copy_as_c_escape(self):
        r"""Copy as C escape sequence: \x4D\x5A\x90\x00"""
        data = self._get_active_bytes()
        if data:
            QApplication.clipboard().setText("".join(f"\\x{b:02X}" for b in data))

    def copy_as_python_bytes(self):
        r"""Copy as Python bytes literal: b'\x4d\x5a\x90\x00'"""
        data = self._get_active_bytes()
        if data:
            QApplication.clipboard().setText("b'" + "".join(f"\\x{b:02x}" for b in data) + "'")

    def copy_as_ascii(self):
        """Copy as ASCII with dots for non-printable: MZ.."""
        data = self._get_active_bytes()
        if data:
            text = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
            QApplication.clipboard().setText(text)

    def copy_as_hex_compact(self):
        """Copy as compact hex (no spaces): 4D5A9000"""
        data = self._get_active_bytes()
        if data:
            QApplication.clipboard().setText("".join(f"{b:02X}" for b in data))

    def copy_hex_to_text(self):
        r"""Copy bytes decoded as UTF-8 text with escapes for non-printable: MZ\x90\x00"""
        data = self._get_active_bytes()
        if data:
            parts = []
            for b in data:
                if 32 <= b <= 126:
                    parts.append(chr(b))
                elif b == 0x0a:
                    parts.append("\\n")
                elif b == 0x0d:
                    parts.append("\\r")
                elif b == 0x09:
                    parts.append("\\t")
                elif b == 0x00:
                    parts.append("\\0")
                else:
                    parts.append(f"\\x{b:02x}")
            QApplication.clipboard().setText("".join(parts))

    def copy_text_to_hex(self):
        """Copy the ASCII text of selected bytes as hex pairs: 4D5A2E2E"""
        data = self._get_active_bytes()
        if data:
            # Represent each byte as hex — same as compact, labelled for text→hex workflow
            QApplication.clipboard().setText(" ".join(f"0x{b:02X}" for b in data))

    def copy_as_base64(self):
        """Copy selected bytes as Base64 encoded string."""
        import base64
        data = self._get_active_bytes()
        if data:
            QApplication.clipboard().setText(base64.b64encode(data).decode("ascii"))

    def generate_yara_pattern(self) -> str:
        """Generate a YARA hex pattern string like: $hex_1 = { 4D 5A 90 00 }  // 0x00000000, 4 bytes"""
        data = self._get_active_bytes()
        if not data:
            return ""
        self._yara_counter += 1
        hex_str = " ".join(f"{b:02X}" for b in data)
        # Determine offset of selected region for the comment
        if self._marker_start >= 0 and self._marker_end >= 0:
            start_off = min(self._marker_start, self._marker_end)
        elif self.has_selection():
            start_off, _ = self._ordered_selection()
        else:
            start_off = self._cursor_offset
        return f"$hex_{self._yara_counter} = {{ {hex_str} }}  // 0x{start_off:08X}, {len(data)} bytes"

    def send_to_yara_editor(self):
        """Generate a YARA pattern and emit yara_pattern_requested."""
        pattern = self.generate_yara_pattern()
        if pattern:
            self.yara_pattern_requested.emit(pattern)

    # ── Marker methods ───────────────────────────────────────────

    def set_marker_start(self):
        """Set the start marker at the current cursor offset."""
        self._marker_start = self._cursor_offset
        if self._marker_end >= 0:
            lo = min(self._marker_start, self._marker_end)
            hi = max(self._marker_start, self._marker_end)
            self._selection_start = lo
            self._selection_end = hi
        self.viewport().update()

    def set_marker_end(self):
        """Set the end marker at the current cursor offset."""
        self._marker_end = self._cursor_offset
        if self._marker_start >= 0:
            lo = min(self._marker_start, self._marker_end)
            hi = max(self._marker_start, self._marker_end)
            self._selection_start = lo
            self._selection_end = hi
        self.viewport().update()

    def clear_markers(self):
        """Clear both markers and the selection they define."""
        self._marker_start = -1
        self._marker_end = -1
        self._selection_start = -1
        self._selection_end = -1
        self.viewport().update()

    # ── Wildcard pattern builder ─────────────────────────────────

    def _get_active_range(self) -> tuple[int, int]:
        """Return (lo, hi) inclusive byte range from markers > selection > cursor."""
        if self._marker_start >= 0 and self._marker_end >= 0:
            return (min(self._marker_start, self._marker_end),
                    max(self._marker_start, self._marker_end))
        if self.has_selection():
            return self._ordered_selection()
        return (self._cursor_offset, self._cursor_offset)

    def add_pattern_region(self, lo: int = -1, hi: int = -1):
        """Append a byte range as a pattern region.

        If *lo*/*hi* are not given, the current selection/markers/cursor are used.
        """
        if lo < 0 or hi < 0:
            lo, hi = self._get_active_range()

        # Merge with overlapping/adjacent existing regions
        new_regions = []
        for rs, re_ in self._pattern_regions:
            if lo <= re_ + 1 and hi >= rs - 1:
                lo = min(lo, rs)
                hi = max(hi, re_)
            else:
                new_regions.append((rs, re_))
        new_regions.append((lo, hi))
        new_regions.sort()
        self._pattern_regions = new_regions
        self.pattern_regions_changed.emit(len(self._pattern_regions))
        self.viewport().update()

    def clear_pattern_regions(self):
        """Reset all pattern regions."""
        self._pattern_regions.clear()
        self.pattern_regions_changed.emit(0)
        self.viewport().update()

    def build_wildcard_pattern(self) -> str:
        """Generate a YARA hex pattern with [N] wildcards between regions."""
        if not self._pattern_regions or not self._buffer:
            return ""
        regions = sorted(self._pattern_regions)
        parts = []
        for i, (start, end) in enumerate(regions):
            data = self._buffer.read(start, end - start + 1)
            hex_bytes = " ".join(f"{b:02X}" for b in data)
            if i > 0:
                prev_end = regions[i - 1][1]
                gap = start - (prev_end + 1)
                if gap > 0:
                    parts.append(f"[{gap}]")
                # gap == 0: adjacent, no wildcard needed
                # gap < 0 should not happen after merge
            parts.append(hex_bytes)

        self._yara_counter += 1
        origin = regions[0][0]
        return (f"$wildcard_{self._yara_counter} = {{ {' '.join(parts)} }}"
                f"  // {len(regions)} regions from 0x{origin:08X}")

    def send_wildcard_to_yara_editor(self):
        """Build wildcard pattern and emit via yara_pattern_requested."""
        pattern = self.build_wildcard_pattern()
        if pattern:
            self.yara_pattern_requested.emit(pattern)

    def send_all_regions_to_yara_editor(self):
        """Send each pattern region as a separate $hex_N pattern."""
        if not self._pattern_regions or not self._buffer:
            return
        lines = []
        for start, end in sorted(self._pattern_regions):
            data = self._buffer.read(start, end - start + 1)
            hex_str = " ".join(f"{b:02X}" for b in data)
            self._yara_counter += 1
            lines.append(f"$hex_{self._yara_counter} = {{ {hex_str} }}"
                         f"  // 0x{start:08X}, {len(data)} bytes")
        if lines:
            self.yara_pattern_requested.emit("\n    ".join(lines))

    # ── Context menu ─────────────────────────────────────────────

    def contextMenuEvent(self, event):
        menu = QMenu(self)

        act_hex = menu.addAction("Copy as Hex                Ctrl+C")
        act_hex.triggered.connect(self.copy_as_hex)

        act_hex_compact = menu.addAction("Copy as Hex (compact)")
        act_hex_compact.triggered.connect(self.copy_as_hex_compact)

        act_yara = menu.addAction("Copy as YARA Hex        Ctrl+Y")
        act_yara.triggered.connect(self.copy_as_yara_hex)

        menu.addSeparator()

        act_h2t = menu.addAction("Hex \u2192 Text (decoded)")
        act_h2t.triggered.connect(self.copy_hex_to_text)

        act_t2h = menu.addAction("Text \u2192 Hex (0x pairs)")
        act_t2h.triggered.connect(self.copy_text_to_hex)

        menu.addSeparator()

        act_c = menu.addAction("Copy as C Escape")
        act_c.triggered.connect(self.copy_as_c_escape)

        act_py = menu.addAction("Copy as Python Bytes")
        act_py.triggered.connect(self.copy_as_python_bytes)

        act_ascii = menu.addAction("Copy as ASCII")
        act_ascii.triggered.connect(self.copy_as_ascii)

        act_b64 = menu.addAction("Copy as Base64")
        act_b64.triggered.connect(self.copy_as_base64)

        menu.addSeparator()

        act_start = menu.addAction("Set Selection Start")
        act_start.triggered.connect(self.set_marker_start)

        act_end = menu.addAction("Set Selection End")
        act_end.triggered.connect(self.set_marker_end)

        act_clear = menu.addAction("Clear Markers")
        act_clear.triggered.connect(self.clear_markers)

        menu.addSeparator()

        act_send = menu.addAction("Send to YARA Editor    Ctrl+Shift+Y")
        act_send.triggered.connect(self.send_to_yara_editor)

        menu.addSeparator()

        act_xform = menu.addAction("Apply Transform\u2026")
        act_xform.triggered.connect(self._request_transform)

        menu.addSeparator()

        # Capture the active range NOW, before menu event loop can change state
        rgn_lo, rgn_hi = self._get_active_range()

        act_add_region = menu.addAction("Mark Region")
        act_add_region.triggered.connect(lambda: self.add_pattern_region(rgn_lo, rgn_hi))

        act_send_regions = menu.addAction("Send Regions to YARA Editor")
        act_send_regions.triggered.connect(self.send_all_regions_to_yara_editor)

        act_build_wc = menu.addAction("Send as Wildcard Pattern")
        act_build_wc.triggered.connect(self.send_wildcard_to_yara_editor)

        act_clear_regions = menu.addAction("Clear Regions")
        act_clear_regions.triggered.connect(self.clear_pattern_regions)

        menu.addSeparator()

        # Capture range for disassemble
        disasm_lo, disasm_hi = self._get_active_range()
        act_disasm = menu.addAction("Disassemble Selection")
        act_disasm.triggered.connect(
            lambda: self._emit_disassemble(disasm_lo, disasm_hi))

        # Disable actions if no data loaded
        has_data = self._buffer is not None and self._buffer.size() > 0
        copy_acts = (act_hex, act_hex_compact, act_yara, act_h2t, act_t2h,
                     act_c, act_py, act_ascii, act_b64, act_send)
        for act in copy_acts:
            act.setEnabled(has_data)
        for act in (act_start, act_end):
            act.setEnabled(has_data)
        act_clear.setEnabled(self._marker_start >= 0 or self._marker_end >= 0)
        act_add_region.setEnabled(has_data)
        act_xform.setEnabled(has_data)
        has_regions = len(self._pattern_regions) >= 1
        act_build_wc.setEnabled(len(self._pattern_regions) >= 2)
        act_send_regions.setEnabled(has_regions)
        act_clear_regions.setEnabled(has_regions)
        act_disasm.setEnabled(has_data and disasm_hi > disasm_lo)

        menu.exec(event.globalPos())

    def _emit_disassemble(self, lo: int, hi: int):
        if self._buffer is None or hi <= lo:
            return
        data = self._buffer.read(lo, hi - lo)
        self.disassemble_requested.emit(bytes(data), lo)

    def _request_transform(self):
        """Ask the window to open the transform dialog for us."""
        self.transform_requested.emit()

    def pattern_regions(self) -> list[tuple[int, int]]:
        """Return the current pattern regions as a sorted list."""
        return sorted(self._pattern_regions)

    def refresh_after_data_change(self):
        """Called by the window after a transform/undo/redo.

        Clamps cursor/selection to the (possibly shorter) buffer and
        forces a repaint.  The window is responsible for pushing the
        buffer into the other docks.
        """
        if self._buffer is None:
            self.viewport().update()
            return
        size = self._buffer.size()
        max_off = max(0, size - 1)
        if self._cursor_offset > max_off:
            self._cursor_offset = max_off
        if self._selection_start > max_off:
            self._selection_start = -1
        if self._selection_end > max_off:
            self._selection_end = max_off if self._selection_start >= 0 else -1
        if self._marker_start > max_off:
            self._marker_start = -1
        if self._marker_end > max_off:
            self._marker_end = -1
        # Clamp pattern regions to the new size
        new_regions: list[tuple[int, int]] = []
        for lo, hi in self._pattern_regions:
            if lo > max_off:
                continue
            new_regions.append((lo, min(hi, max_off)))
        if new_regions != self._pattern_regions:
            self._pattern_regions = new_regions
            self.pattern_regions_changed.emit(len(new_regions))
        self._update_scrollbar()
        self.cursor_moved.emit(self._cursor_offset)
        self.viewport().update()

    # ── Scrolling / navigation ──────────────────────────────────────

    def _ensure_visible(self, offset: int):
        """Scroll so *offset* is visible — keeps it near the top third for keyboard nav."""
        bpl = self._bytes_per_line()
        line = offset // bpl
        first = self.verticalScrollBar().value()
        visible = self._visible_lines()
        if line < first or line >= first + visible:
            target = max(0, line - visible // 3)
            self.verticalScrollBar().setValue(target)

    def _scroll_to_center(self, offset: int):
        """Scroll so *offset* line is centred vertically (used by navigate_to_offset)."""
        bpl = self._bytes_per_line()
        line = offset // bpl
        visible = self._visible_lines()
        target = max(0, line - visible // 3)
        self.verticalScrollBar().setValue(target)

    def navigate_to_offset(self, offset: int, length: int = 0):
        """Scroll to and highlight a byte range."""
        if not self._buffer:
            return
        offset = max(0, min(offset, self._buffer.size() - 1))
        had_selection = self.has_selection()
        self._cursor_offset = offset
        if length > 0:
            self._selection_start = offset
            self._selection_end = min(offset + length - 1, self._buffer.size() - 1)
            self.selection_changed.emit(self._selection_start,
                                        self._selection_end - self._selection_start + 1)
        else:
            self._selection_start = -1
            self._selection_end = -1
            if had_selection:
                self.selection_changed.emit(offset, 0)
        self._scroll_to_center(offset)
        self.cursor_moved.emit(offset)
        self.viewport().update()

    def wheelEvent(self, event: QWheelEvent):
        delta = event.angleDelta().y()
        steps = -delta // 40  # 3 lines per notch
        self.verticalScrollBar().setValue(self.verticalScrollBar().value() + steps)
        event.accept()
