# -*- coding: utf-8 -*-
"""Core hex view widget using QAbstractScrollArea with custom painting.

Refactored to follow the Single Responsibility Principle:
- **SelectionModel** owns cursor/selection/marker/region state
- **HexLayout** owns column metrics and coordinate mapping
- **HexPainter** strategies handle all rendering
- **ClipboardExporter** handles copy/format/YARA operations
- **HexWidget** is the thin controller that wires input events to the model
  and triggers repaints.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import (QFont, QFontMetrics, QPainter, QColor,
                           QKeyEvent, QMouseEvent, QAction)
from PySide6.QtWidgets import (QAbstractScrollArea, QApplication, QMenu,
                               QInputDialog, QMessageBox)

from .hex_data_buffer import HexDataBuffer
from .selection_model import SelectionModel
from .hex_layout import HexLayout
from .hex_painter import (PaintContext, HexModePainter, TextEscapePainter,
                          TextNotepadPainter)
from .clipboard_exporter import ClipboardExporter
from .edit_controller import EditController


class HexWidget(QAbstractScrollArea):
    """Custom hex view widget rendering offset | hex | ASCII columns.

    Acts as the **Controller** in an MVC-style decomposition:
    - Model: SelectionModel + HexDataBuffer
    - View: HexPainter strategies
    - Controller: this class (input dispatch + signal wiring)
    """

    cursor_moved = Signal(int)
    selection_changed = Signal(int, int)
    yara_pattern_requested = Signal(str)
    pattern_regions_changed = Signal(int)
    disassemble_requested = Signal(bytes, int)
    transform_requested = Signal()
    bytes_per_line_changed = Signal(int)
    data_edited = Signal()  # emitted after any byte edit (type/delete/paste/fill/undo/redo)
    read_only_changed = Signal(bool)  # emitted when lock state changes

    def __init__(self, parent=None):
        super().__init__(parent)

        # ── Composed subsystems ────────────────────────────────────
        self._buffer: HexDataBuffer | None = None
        self._selection = SelectionModel(self)
        self._layout = HexLayout()
        self._exporter = ClipboardExporter(None, self._selection)
        self._editor = EditController()
        self._read_only: bool = True  # locked by default — user must unlock to edit
        self._gutter_mode: str = "offset"  # "offset" or "line"
        self._diff_regions: list[tuple[int, int]] = []  # (start, end) for binary diff

        # Forward SelectionModel signals to our public API
        self._selection.cursor_moved.connect(self.cursor_moved.emit)
        self._selection.selection_changed.connect(self.selection_changed.emit)

        # ── View mode state ────────────────────────────────────────
        self._text_mode = False
        self._text_escape_mode = False
        self._text_line_starts: list[int] = []

        # ── Paint strategies (instantiated on demand) ──────────────
        self._hex_painter = HexModePainter()
        self._text_escape_painter = TextEscapePainter()

        # ── Theme colours (defaults — overridden by set_theme) ─────
        self._offset_bg = QColor("#f0f0f0")
        self._offset_text = QColor("#666666")
        self._hex_text = QColor("#000000")
        self._ascii_text = QColor("#0066cc")
        self._ascii_nonprint = QColor("#cccccc")
        self._cursor_bg = QColor("#3399ff")
        self._separator = QColor("#cccccc")
        self._bg = QColor("#ffffff")
        self._selection_bg = QColor(51, 153, 255, 160)
        self._pattern_region_color = QColor(255, 165, 0, 100)

        # ── Font setup ─────────────────────────────────────────────
        self._font = QFont()
        self._font.setFamilies([
            "Cascadia Mono", "Consolas", "Courier New",
            "DejaVu Sans Mono", "monospace",
        ])
        self._font.setPointSize(10)
        self._font.setStyleHint(QFont.StyleHint.Monospace,
                                QFont.StyleStrategy.PreferDefault)
        self._font.setFixedPitch(True)
        self._font.setKerning(False)
        self.setFont(self._font)

        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

    # ── Properties (public API preserved) ──────────────────────────

    @property
    def selection_model(self) -> SelectionModel:
        return self._selection

    @property
    def layout_info(self) -> HexLayout:
        return self._layout

    @property
    def exporter(self) -> ClipboardExporter:
        return self._exporter

    @property
    def read_only(self) -> bool:
        return self._read_only

    @read_only.setter
    def read_only(self, value: bool):
        if self._read_only != value:
            self._read_only = value
            self.read_only_changed.emit(value)
            self.viewport().update()

    def _check_editable(self) -> bool:
        """Return True if editing is allowed. False = locked (read-only)."""
        return not self._read_only

    def set_diff_regions(self, regions: list[tuple[int, int]]):
        """Set sorted list of (start, end_exclusive) byte ranges to highlight as diffs."""
        self._diff_regions = list(regions)
        self.viewport().update()

    def clear_diff_regions(self):
        self._diff_regions = []
        self.viewport().update()

    @property
    def gutter_mode(self) -> str:
        """'offset' for hex addresses, 'line' for 1-based line numbers."""
        return self._gutter_mode

    @gutter_mode.setter
    def gutter_mode(self, mode: str):
        if mode not in ("offset", "line"):
            return
        if self._gutter_mode != mode:
            self._gutter_mode = mode
            self.viewport().update()

    # ── Font / metrics ─────────────────────────────────────────────

    def setFont(self, font):
        super().setFont(font)
        self._font = font
        self._layout.update_metrics(QFontMetrics(font))
        self.viewport().update()

    # ── Data binding ───────────────────────────────────────────────

    def set_buffer(self, buf: HexDataBuffer):
        self._buffer = buf
        self._exporter.set_buffer(buf)
        self._editor.set_buffer(buf)
        self._selection.reset()
        self._text_line_starts = []
        if self._text_mode and not self._text_escape_mode:
            self._rebuild_text_line_starts()
        self._update_scrollbar()
        self.viewport().update()
        self._selection.cursor_moved.emit(0)

    def bytes_per_line(self) -> int:
        return self._layout.bytes_per_line_hex

    def set_bytes_per_line(self, n: int):
        if not self._layout.set_bytes_per_line(n):
            return
        self._layout.update_metrics(QFontMetrics(self._font))
        self._update_scrollbar()
        if self._buffer is not None:
            self._ensure_visible(self._selection.cursor)
        self.viewport().update()
        self.bytes_per_line_changed.emit(self._layout.bytes_per_line_hex)

    # ── View mode ──────────────────────────────────────────────────

    def set_text_mode(self, enabled: bool):
        if self._text_mode == enabled:
            return
        self._text_mode = enabled
        # Auto-switch gutter: line numbers for text, offsets for hex
        self._gutter_mode = "line" if enabled else "offset"
        if enabled and not self._text_escape_mode:
            self._rebuild_text_line_starts()
        self._update_scrollbar()
        self.viewport().update()

    def text_escape_mode(self) -> bool:
        return self._text_escape_mode

    def set_text_escape_mode(self, enabled: bool):
        if self._text_escape_mode == enabled:
            return
        self._text_escape_mode = enabled
        if self._text_mode and not enabled:
            self._rebuild_text_line_starts()
        self._update_scrollbar()
        self.viewport().update()

    # ── Text line index ────────────────────────────────────────────

    def _rebuild_text_line_starts(self):
        self._text_line_starts = [0]
        if self._buffer is None or self._buffer.size() == 0:
            return
        CHUNK = 1 << 20
        size = self._buffer.size()
        off = 0
        while off < size:
            data = self._buffer.read(off, min(CHUNK, size - off))
            i = 0
            n = len(data)
            while True:
                j = data.find(b"\n", i)
                if j < 0:
                    break
                start = off + j + 1
                if start < size:
                    self._text_line_starts.append(start)
                i = j + 1
            off += n

    def _byte_to_text_line(self, offset: int) -> int:
        if not self._text_line_starts:
            self._rebuild_text_line_starts()
        starts = self._text_line_starts
        if not starts:
            return 0
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo

    def _line_col_to_offset(self, line_idx: int, col: int) -> int:
        starts = self._text_line_starts
        if not starts or self._buffer is None:
            return 0
        size = self._buffer.size()
        line_idx = max(0, min(line_idx, len(starts) - 1))
        line_start = starts[line_idx]
        line_end = starts[line_idx + 1] if line_idx + 1 < len(starts) else size
        content_end = line_end
        if content_end > line_start and self._buffer.read(content_end - 1, 1) == b"\n":
            content_end -= 1
        if content_end > line_start and self._buffer.read(content_end - 1, 1) == b"\r":
            content_end -= 1
        content_len = max(0, content_end - line_start)
        col = max(0, min(col, content_len))
        return min(line_start + col, max(0, size - 1))

    # ── Scrollbar ──────────────────────────────────────────────────

    def _visible_lines(self) -> int:
        return self._layout.visible_lines(self.viewport().height())

    def _update_scrollbar(self):
        if not self._buffer:
            total = 0
        elif self._text_mode and not self._text_escape_mode:
            if not self._text_line_starts:
                self._rebuild_text_line_starts()
            total = len(self._text_line_starts)
        else:
            total = self._layout.total_lines(
                self._buffer.size() if self._buffer else 0,
                self._text_mode, 0)
        visible = self._visible_lines()
        self.verticalScrollBar().setRange(0, max(0, total - visible))
        self.verticalScrollBar().setPageStep(visible)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_scrollbar()

    # ── Theme ──────────────────────────────────────────────────────

    def set_theme(self, colors):
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

        bg = getattr(colors, "editor_background", None)
        if bg:
            self._bg = QColor(bg)
        sel = getattr(colors, "selection_background", None)
        if sel:
            c = QColor(sel)
            c.setAlpha(160)
            self._selection_bg = c

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

    # ── Painting ───────────────────────────────────────────────────

    def paintEvent(self, event):
        if not self._buffer or self._buffer.size() == 0:
            painter = QPainter(self.viewport())
            painter.fillRect(self.viewport().rect(), self._bg)
            painter.setPen(self._offset_text)
            painter.drawText(self.viewport().rect(), Qt.AlignmentFlag.AlignCenter,
                             "No file loaded \u2014 use File > Open or drag a file")
            painter.end()
            return

        # Compute the visible-window diff offsets so we don't materialise
        # a huge set for files with millions of differing bytes.
        diff_offsets: set[int] = set()
        if self._diff_regions:
            bpl = self._layout.bytes_per_line(self._text_mode)
            first_line = self.verticalScrollBar().value()
            visible = self._visible_lines() + 1
            vis_lo = first_line * bpl
            vis_hi = vis_lo + visible * bpl
            for r_start, r_end in self._diff_regions:
                if r_end <= vis_lo:
                    continue
                if r_start >= vis_hi:
                    break
                for off in range(max(r_start, vis_lo), min(r_end, vis_hi)):
                    diff_offsets.add(off)

        ctx = PaintContext(
            buffer=self._buffer,
            layout=self._layout,
            selection=self._selection,
            font=self._font,
            first_line=self.verticalScrollBar().value(),
            visible_lines=self._visible_lines(),
            viewport_width=self.viewport().width(),
            bg=self._bg,
            offset_bg=self._offset_bg,
            offset_text=self._offset_text,
            hex_text=self._hex_text,
            ascii_text=self._ascii_text,
            ascii_nonprint=self._ascii_nonprint,
            cursor_bg=self._cursor_bg,
            selection_bg=self._selection_bg,
            separator=self._separator,
            pattern_region_color=self._pattern_region_color,
            modified_offsets=self._editor.modified_offsets,
            gutter_mode=self._gutter_mode,
            diff_offsets=diff_offsets,
        )

        painter = QPainter(self.viewport())
        strategy = self._current_paint_strategy()
        strategy.paint(painter, ctx)
        painter.end()

    def _current_paint_strategy(self):
        if self._text_mode:
            if self._text_escape_mode:
                return self._text_escape_painter
            if not self._text_line_starts:
                self._rebuild_text_line_starts()
            return TextNotepadPainter(self._text_line_starts)
        return self._hex_painter

    # ── Selection helpers (public API preserved) ───────────────────

    def _ordered_selection(self):
        return self._selection.ordered_selection()

    def has_selection(self) -> bool:
        return self._selection.has_selection()

    def selected_bytes(self) -> bytes:
        if not self.has_selection() or not self._buffer:
            return b""
        lo, hi = self._ordered_selection()
        return self._buffer.read(lo, hi - lo + 1)

    # ── Mouse events ───────────────────────────────────────────────

    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.MouseButton.LeftButton:
            off = self._layout.offset_from_point(
                event.position().toPoint(),
                self.verticalScrollBar().value(),
                self._buffer, self._text_mode, self._text_escape_mode,
                self._text_line_starts, self._rebuild_text_line_starts)
            if off >= 0:
                if self._text_mode:
                    self._selection.focus_ascii = True
                else:
                    x = event.position().toPoint().x()
                    self._selection.focus_ascii = self._layout.is_in_ascii_area(x)

                if event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                    self._selection.extend_selection(off)
                else:
                    self._selection.begin_selection(off)
                self.viewport().update()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent):
        if self._selection.selecting:
            off = self._layout.offset_from_point(
                event.position().toPoint(),
                self.verticalScrollBar().value(),
                self._buffer, self._text_mode, self._text_escape_mode,
                self._text_line_starts, self._rebuild_text_line_starts)
            if off >= 0:
                self._selection.extend_selection(off)
                self.viewport().update()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent):
        if event.button() == Qt.MouseButton.LeftButton:
            self._selection.finish_selection()
        super().mouseReleaseEvent(event)

    # ── Keyboard events ────────────────────────────────────────────

    _HEX_CHARS = set("0123456789abcdefABCDEF")

    def keyPressEvent(self, event: QKeyEvent):
        if not self._buffer or self._buffer.size() == 0:
            super().keyPressEvent(event)
            return

        max_off = self._buffer.size() - 1
        shift = bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier)
        ctrl = bool(event.modifiers() & Qt.KeyboardModifier.ControlModifier)
        key = event.key()
        cur = self._selection.cursor
        new_off = cur
        ch = event.text()

        bpl = self._layout.bytes_per_line(self._text_mode)
        notepad = self._text_mode and not self._text_escape_mode

        # ── Edit hotkeys (Ctrl combos first) ───────────────────────
        # All mutating actions are gated on _check_editable().

        if key == Qt.Key.Key_Z and ctrl and shift:
            if self._check_editable():
                self._do_redo()
            return
        if key == Qt.Key.Key_Z and ctrl:
            if self._check_editable():
                self._do_undo()
            return
        if key == Qt.Key.Key_V and ctrl:
            if self._check_editable():
                self._do_paste()
            return
        if key == Qt.Key.Key_I and ctrl:
            if self._check_editable():
                self._do_insert_dialog()
            return
        if key == Qt.Key.Key_F and ctrl and shift:
            if self._check_editable():
                self._do_fill_dialog()
            return

        # ── Standard hotkeys ───────────────────────────────────────

        if key == Qt.Key.Key_C and ctrl:
            self._exporter.copy_smart(self._selection.focus_ascii)
            return
        if key == Qt.Key.Key_Y and ctrl and shift:
            self.send_to_yara_editor()
            return
        if key == Qt.Key.Key_Y and ctrl:
            self._exporter.copy("yara_hex")
            return

        # ── Insert mode toggle ─────────────────────────────────────

        if key == Qt.Key.Key_Insert:
            if self._check_editable():
                self._editor.toggle_insert_mode()
                self.viewport().update()
            return

        # ── Delete / Backspace ─────────────────────────────────────

        if key == Qt.Key.Key_Delete:
            if not self._check_editable():
                return
            if self._selection.has_selection():
                lo, hi = self._selection.ordered_selection()
                cmd = self._editor.delete_selection(lo, hi)
            else:
                cmd = self._editor.delete_at(cur, 1)
            if cmd:
                self._selection.clear_selection()
                self._selection.set_cursor(cmd.cursor_after, emit=False)
                self._after_edit()
            return

        if key == Qt.Key.Key_Backspace:
            if not self._check_editable():
                return
            if self._selection.has_selection():
                lo, hi = self._selection.ordered_selection()
                cmd = self._editor.delete_selection(lo, hi)
                if cmd:
                    self._selection.clear_selection()
                    self._selection.set_cursor(cmd.cursor_after, emit=False)
                    self._after_edit()
            else:
                cmd = self._editor.backspace(cur)
                if cmd:
                    self._selection.set_cursor(cmd.cursor_after, emit=False)
                    self._after_edit()
            return

        # ── Hex digit typing (in hex column, not text mode) ────────

        if (not self._text_mode and not self._selection.focus_ascii
                and not ctrl and not shift
                and len(ch) == 1 and ch in self._HEX_CHARS):
            if not self._check_editable():
                return
            nibble = int(ch, 16)
            cmd = self._editor.type_hex_nibble(cur, nibble)
            if cmd:
                self._selection.clear_selection()
                self._selection.set_cursor(cmd.cursor_after, emit=False)
                self._after_edit()
            return

        # ── ASCII typing (in ASCII column or text mode) ────────────

        if ((self._selection.focus_ascii or self._text_mode)
                and not ctrl and len(ch) == 1 and ch.isprintable()):
            if not self._check_editable():
                return
            cmd = self._editor.type_ascii_char(cur, ch)
            if cmd:
                self._selection.clear_selection()
                self._selection.set_cursor(cmd.cursor_after, emit=False)
                self._after_edit()
            return

        # ── Navigation keys ────────────────────────────────────────

        if notepad and key in (Qt.Key.Key_Up, Qt.Key.Key_Down,
                                Qt.Key.Key_PageUp, Qt.Key.Key_PageDown,
                                Qt.Key.Key_Home, Qt.Key.Key_End):
            starts = self._text_line_starts
            if not starts:
                self._rebuild_text_line_starts()
                starts = self._text_line_starts
            cur_line = self._byte_to_text_line(cur)
            cur_col = cur - starts[cur_line]
            if key == Qt.Key.Key_Up:
                new_off = self._line_col_to_offset(max(0, cur_line - 1), cur_col)
            elif key == Qt.Key.Key_Down:
                new_off = self._line_col_to_offset(min(len(starts) - 1, cur_line + 1), cur_col)
            elif key == Qt.Key.Key_PageDown:
                step = max(1, self._visible_lines())
                new_off = self._line_col_to_offset(min(len(starts) - 1, cur_line + step), cur_col)
            elif key == Qt.Key.Key_PageUp:
                step = max(1, self._visible_lines())
                new_off = self._line_col_to_offset(max(0, cur_line - step), cur_col)
            elif key == Qt.Key.Key_Home:
                new_off = 0 if ctrl else starts[cur_line]
            elif key == Qt.Key.Key_End:
                new_off = max_off if ctrl else self._line_col_to_offset(cur_line, 1 << 30)
        elif key == Qt.Key.Key_Right:
            new_off = min(cur + 1, max_off)
        elif key == Qt.Key.Key_Left:
            new_off = max(cur - 1, 0)
        elif key == Qt.Key.Key_Down:
            new_off = min(cur + bpl, max_off)
        elif key == Qt.Key.Key_Up:
            new_off = max(cur - bpl, 0)
        elif key == Qt.Key.Key_PageDown:
            new_off = min(cur + self._visible_lines() * bpl, max_off)
        elif key == Qt.Key.Key_PageUp:
            new_off = max(cur - self._visible_lines() * bpl, 0)
        elif key == Qt.Key.Key_Home:
            new_off = 0 if ctrl else (cur // bpl) * bpl
        elif key == Qt.Key.Key_End:
            new_off = max_off if ctrl else min((cur // bpl) * bpl + bpl - 1, max_off)
        elif key == Qt.Key.Key_Tab:
            self._selection.focus_ascii = not self._selection.focus_ascii
            self.viewport().update()
            return
        else:
            super().keyPressEvent(event)
            return

        # Clear nibble state on any navigation
        self._editor._clear_nibble()

        had_selection = self._selection.has_selection()
        if shift:
            self._selection.shift_extend(new_off)
        else:
            self._selection.clear_selection()

        self._selection.set_cursor(new_off)
        self._ensure_visible(new_off)

        if shift and self._selection.has_selection():
            lo, hi = self._selection.ordered_selection()
            self.selection_changed.emit(lo, hi - lo + 1)
        elif had_selection:
            self.selection_changed.emit(new_off, 0)

        self.viewport().update()

    # ── Edit action helpers ────────────────────────────────────────

    def _after_edit(self):
        """Refresh everything after a byte edit."""
        self.refresh_after_data_change()
        self._ensure_visible(self._selection.cursor)
        self.data_edited.emit()

    def _do_undo(self):
        if not self._check_editable():
            return
        cmd = self._editor.undo()
        if cmd:
            self._selection.clear_selection()
            self._selection.set_cursor(cmd.cursor_before, emit=False)
            self._after_edit()

    def _do_redo(self):
        if not self._check_editable():
            return
        cmd = self._editor.redo()
        if cmd:
            self._selection.clear_selection()
            self._selection.set_cursor(cmd.cursor_after, emit=False)
            self._after_edit()

    def _do_paste(self):
        """Paste from clipboard — parse hex if in hex column, ASCII otherwise."""
        if not self._check_editable():
            return
        text = QApplication.clipboard().text()
        if not text:
            return
        cur = self._selection.cursor

        if self._selection.focus_ascii or self._text_mode:
            data = text.encode("utf-8", errors="replace")
        else:
            # Try to parse as hex (space-separated, compact, or 0x-prefixed)
            cleaned = text.strip().replace("0x", "").replace(",", " ")
            cleaned = " ".join(cleaned.split())
            try:
                if " " in cleaned:
                    data = bytes(int(b, 16) for b in cleaned.split())
                else:
                    data = bytes.fromhex(cleaned)
            except (ValueError, IndexError):
                data = text.encode("utf-8", errors="replace")

        if not data:
            return

        if self._editor.insert_mode:
            cmd = self._editor.paste_insert(cur, data)
        else:
            cmd = self._editor.paste_overwrite(cur, data)
        if cmd:
            self._selection.clear_selection()
            self._selection.set_cursor(cmd.cursor_after, emit=False)
            self._after_edit()

    def _do_insert_dialog(self):
        """Show a dialog to insert N bytes at the cursor."""
        if not self._check_editable():
            return
        text, ok = QInputDialog.getText(
            self, "Insert Bytes",
            "Hex bytes to insert (e.g. 00 00 00 or 4D5A90):",
        )
        if not ok or not text.strip():
            return
        cleaned = text.strip().replace("0x", "").replace(",", " ")
        cleaned = " ".join(cleaned.split())
        try:
            if " " in cleaned:
                data = bytes(int(b, 16) for b in cleaned.split())
            else:
                data = bytes.fromhex(cleaned)
        except (ValueError, IndexError):
            QMessageBox.warning(self, "Invalid hex",
                                f"Could not parse hex: {text}")
            return
        if not data:
            return
        cmd = self._editor.insert_bytes(self._selection.cursor, data)
        if cmd:
            self._selection.clear_selection()
            self._selection.set_cursor(cmd.cursor_after, emit=False)
            self._after_edit()

    def _do_fill_dialog(self):
        """Fill selection with a repeating byte pattern."""
        if not self._check_editable():
            return
        if not self._selection.has_selection():
            QMessageBox.information(self, "No selection",
                                    "Select a byte range first, then Ctrl+Shift+F to fill.")
            return
        lo, hi = self._selection.ordered_selection()
        length = hi - lo + 1
        text, ok = QInputDialog.getText(
            self, "Fill Selection",
            f"Fill {length} byte(s) at 0x{lo:X}-0x{hi:X} with pattern\n"
            f"(e.g. 00, 90, CC, DEADBEEF):",
            text="00",
        )
        if not ok or not text.strip():
            return
        cleaned = text.strip().replace("0x", "").replace(",", " ").replace(" ", "")
        try:
            pattern = bytes.fromhex(cleaned)
        except ValueError:
            QMessageBox.warning(self, "Invalid hex",
                                f"Could not parse hex pattern: {text}")
            return
        if not pattern:
            return
        cmd = self._editor.fill_range(lo, hi, pattern)
        if cmd:
            self._after_edit()

    # ── Copy methods (delegate to exporter, preserve public API) ───

    def copy_as_hex(self):
        self._exporter.copy("hex")

    def copy_as_yara_hex(self):
        self._exporter.copy("yara_hex")

    def copy_as_c_escape(self):
        self._exporter.copy("c_escape")

    def copy_as_python_bytes(self):
        self._exporter.copy("python_bytes")

    def copy_as_ascii(self):
        self._exporter.copy("ascii")

    def copy_as_hex_compact(self):
        self._exporter.copy("hex_compact")

    def copy_hex_to_text(self):
        self._exporter.copy("hex_to_text")

    def copy_text_to_hex(self):
        self._exporter.copy("text_to_hex")

    def copy_as_base64(self):
        self._exporter.copy("base64")

    # ── YARA methods (delegate to exporter) ────────────────────────

    def generate_yara_pattern(self) -> str:
        return self._exporter.generate_yara_pattern()

    def send_to_yara_editor(self):
        pattern = self._exporter.generate_yara_pattern()
        if pattern:
            self.yara_pattern_requested.emit(pattern)

    def send_ascii_to_yara_editor(self):
        pattern = self._exporter.generate_yara_ascii()
        if pattern:
            self.yara_pattern_requested.emit(pattern)

    def send_regex_to_yara_editor(self):
        pattern = self._exporter.generate_yara_regex()
        if pattern:
            self.yara_pattern_requested.emit(pattern)

    def send_wildcard_to_yara_editor(self):
        pattern = self._exporter.build_wildcard_pattern()
        if pattern:
            self.yara_pattern_requested.emit(pattern)

    def send_all_regions_to_yara_editor(self):
        patterns = self._exporter.generate_all_region_patterns()
        if patterns:
            self.yara_pattern_requested.emit(patterns)

    # ── Marker methods (delegate to selection model) ───────────────

    def set_marker_start(self):
        self._selection.set_marker_start()
        self.viewport().update()

    def set_marker_end(self):
        self._selection.set_marker_end()
        self.viewport().update()

    def clear_markers(self):
        self._selection.clear_markers()
        self.viewport().update()

    # ── Pattern region methods (delegate to selection model) ───────

    def add_pattern_region(self, lo: int = -1, hi: int = -1):
        count = self._selection.add_pattern_region(lo, hi)
        self.pattern_regions_changed.emit(count)
        self.viewport().update()

    def clear_pattern_regions(self):
        self._selection.clear_pattern_regions()
        self.pattern_regions_changed.emit(0)
        self.viewport().update()

    def pattern_regions(self) -> list[tuple[int, int]]:
        return self._selection.pattern_regions

    def build_wildcard_pattern(self) -> str:
        return self._exporter.build_wildcard_pattern()

    # ── Navigation ─────────────────────────────────────────────────

    def _ensure_visible(self, offset: int):
        line = self._layout.line_for_offset(
            offset, self._text_mode, self._text_escape_mode,
            self._byte_to_text_line)
        first = self.verticalScrollBar().value()
        visible = self._visible_lines()
        if line < first or line >= first + visible:
            target = max(0, line - visible // 3)
            self.verticalScrollBar().setValue(target)

    def navigate_to_offset(self, offset: int, length: int = 0):
        if not self._buffer:
            return
        offset = max(0, min(offset, self._buffer.size() - 1))
        had_selection = self._selection.has_selection()
        self._selection.set_cursor(offset, emit=False)
        if length > 0:
            end = min(offset + length - 1, self._buffer.size() - 1)
            self._selection.set_selection(offset, end)
            self.selection_changed.emit(offset, end - offset + 1)
        else:
            self._selection.clear_selection()
            if had_selection:
                self.selection_changed.emit(offset, 0)

        line = self._layout.line_for_offset(
            offset, self._text_mode, self._text_escape_mode,
            self._byte_to_text_line)
        visible = self._visible_lines()
        target = max(0, line - visible // 3)
        self.verticalScrollBar().setValue(target)
        self.cursor_moved.emit(offset)
        self.viewport().update()

    # ── Post-transform refresh ─────────────────────────────────────

    def refresh_after_data_change(self):
        if self._buffer is None:
            self.viewport().update()
            return
        self._selection.clamp_to_size(self._buffer.size())
        prev_count = self._selection.pattern_region_count
        self._selection.clamp_to_size(self._buffer.size())
        if self._selection.pattern_region_count != prev_count:
            self.pattern_regions_changed.emit(self._selection.pattern_region_count)
        self._text_line_starts = []
        if self._text_mode and not self._text_escape_mode:
            self._rebuild_text_line_starts()
        self._update_scrollbar()
        self.cursor_moved.emit(self._selection.cursor)
        self.viewport().update()

    # ── Context menu ─────────────────────────────────────────────

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        sel = self._selection

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

        yara_menu = menu.addMenu("Send to YARA Editor")
        act_send_hex = yara_menu.addAction("As Hex Pattern    { AA BB CC }")
        act_send_hex.triggered.connect(self.send_to_yara_editor)
        act_send_ascii = yara_menu.addAction('As ASCII String    "text"')
        act_send_ascii.triggered.connect(self.send_ascii_to_yara_editor)
        act_send_regex = yara_menu.addAction("As Regex    /pattern/")
        act_send_regex.triggered.connect(self.send_regex_to_yara_editor)

        menu.addSeparator()

        act_xform = menu.addAction("Apply Transform\u2026")
        act_xform.triggered.connect(lambda: self.transform_requested.emit())

        menu.addSeparator()

        # Capture active range before menu event loop
        rgn_lo, rgn_hi = sel.active_range()

        act_add_region = menu.addAction("Mark Region")
        act_add_region.triggered.connect(lambda: self.add_pattern_region(rgn_lo, rgn_hi))

        act_send_regions = menu.addAction("Send Regions to YARA Editor")
        act_send_regions.triggered.connect(self.send_all_regions_to_yara_editor)

        act_build_wc = menu.addAction("Send as Wildcard Pattern")
        act_build_wc.triggered.connect(self.send_wildcard_to_yara_editor)

        act_clear_regions = menu.addAction("Clear Regions")
        act_clear_regions.triggered.connect(self.clear_pattern_regions)

        menu.addSeparator()

        disasm_lo, disasm_hi = sel.active_range()
        act_disasm = menu.addAction("Disassemble Selection")
        act_disasm.triggered.connect(lambda: self._emit_disassemble(disasm_lo, disasm_hi))

        # ── Edit operations ────────────────────────────────────────
        menu.addSeparator()
        edit_lo, edit_hi = sel.active_range()
        edit_len = edit_hi - edit_lo + 1

        act_nop = menu.addAction(f"NOP Selection (0x90, {edit_len} bytes)")
        act_nop.triggered.connect(lambda: self._do_nop(edit_lo, edit_hi))

        act_zero = menu.addAction(f"Zero Selection (0x00, {edit_len} bytes)")
        act_zero.triggered.connect(lambda: self._do_zero(edit_lo, edit_hi))

        act_fill = menu.addAction("Fill Selection\u2026        Ctrl+Shift+F")
        act_fill.triggered.connect(self._do_fill_dialog)

        act_insert = menu.addAction("Insert Bytes\u2026          Ctrl+I")
        act_insert.triggered.connect(self._do_insert_dialog)

        act_delete = menu.addAction("Delete Selection         Del")
        act_delete.triggered.connect(lambda: self._do_delete_selection())

        menu.addSeparator()

        act_undo = menu.addAction("Undo                     Ctrl+Z")
        act_undo.triggered.connect(self._do_undo)

        act_redo = menu.addAction("Redo                     Ctrl+Shift+Z")
        act_redo.triggered.connect(self._do_redo)

        act_paste = menu.addAction("Paste                    Ctrl+V")
        act_paste.triggered.connect(self._do_paste)

        mode_label = "Insert" if self._editor.insert_mode else "Overwrite"
        act_mode = menu.addAction(f"Mode: {mode_label}         Ins")
        act_mode.triggered.connect(lambda: self._editor.toggle_insert_mode())

        # Enable/disable based on state
        has_data = self._buffer is not None and self._buffer.size() > 0
        has_sel = sel.has_selection()
        for act in (act_hex, act_hex_compact, act_yara, act_h2t, act_t2h,
                    act_c, act_py, act_ascii, act_b64):
            act.setEnabled(has_data)
        yara_menu.setEnabled(has_data)
        act_start.setEnabled(has_data)
        act_end.setEnabled(has_data)
        act_clear.setEnabled(sel.marker_start >= 0 or sel.marker_end >= 0)
        act_add_region.setEnabled(has_data)
        act_xform.setEnabled(has_data)
        has_regions = sel.pattern_region_count >= 1
        act_build_wc.setEnabled(sel.pattern_region_count >= 2)
        act_send_regions.setEnabled(has_regions)
        act_clear_regions.setEnabled(has_regions)
        act_disasm.setEnabled(has_data and disasm_hi > disasm_lo)
        editable = not self._read_only
        act_nop.setEnabled(has_data and has_sel and editable)
        act_zero.setEnabled(has_data and has_sel and editable)
        act_fill.setEnabled(has_data and has_sel and editable)
        act_delete.setEnabled(has_data and has_sel and editable)
        act_insert.setEnabled(has_data and editable)
        act_undo.setEnabled(self._editor.has_undo() and editable)
        act_redo.setEnabled(self._editor.has_redo() and editable)
        act_paste.setEnabled(has_data and editable)
        act_mode.setEnabled(editable)
        act_xform.setEnabled(has_data and editable)

        menu.exec(event.globalPos())

    def _do_nop(self, lo: int, hi: int):
        """Fill selection with 0x90 (x86 NOP)."""
        if not self._check_editable():
            return
        cmd = self._editor.fill_range(lo, hi, b"\x90")
        if cmd:
            self._after_edit()

    def _do_zero(self, lo: int, hi: int):
        """Fill selection with 0x00."""
        if not self._check_editable():
            return
        cmd = self._editor.fill_range(lo, hi, b"\x00")
        if cmd:
            self._after_edit()

    def _do_delete_selection(self):
        if not self._check_editable():
            return
        if not self._selection.has_selection():
            return
        lo, hi = self._selection.ordered_selection()
        cmd = self._editor.delete_selection(lo, hi)
        if cmd:
            self._selection.clear_selection()
            self._selection.set_cursor(cmd.cursor_after, emit=False)
            self._after_edit()

    def _emit_disassemble(self, lo: int, hi: int):
        if self._buffer is None or hi <= lo:
            return
        data = self._buffer.read(lo, hi - lo)
        self.disassemble_requested.emit(bytes(data), lo)
