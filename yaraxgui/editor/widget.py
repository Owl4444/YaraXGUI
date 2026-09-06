# This Python file uses the following encoding: utf-8

"""
YaraTextEdit - QPlainTextEdit subclass with built-in line numbers, current line
highlighting, cursor position reporting, word wrap toggle, monospace font setup,
and optional vim-style keybindings.
"""

import re

from PySide6.QtCore import QRect, QSize, Qt, QTimer, Signal, QPointF
from PySide6.QtCore import QMimeData
from PySide6.QtCore import QEvent
from PySide6.QtGui import (QColor, QFont, QPainter, QPen, QTextCharFormat,
                           QTextCursor, QTextFormat)
from PySide6.QtWidgets import QApplication, QPlainTextEdit, QTextEdit, QToolTip, QWidget

from yaraxgui.editor.vim import VimHandler, VimMode
from yaraxgui.editor.completer import CompletionItem, CompletionPopup
from yaraxgui.editor.backend import EditorBackend, automatic_document_allowed
from yarax_editor import CompileOptions, SourceMap, Document, Span
from yarax_editor.lexer import noncode_at
from yarax_editor.editing import expand_snippet, newline_edit
from yarax_editor.formatting_jobs import check_source_size


class _LineNumberArea(QWidget):
    """Widget that paints line numbers alongside the editor."""

    def __init__(self, editor: "YaraTextEdit"):
        super().__init__(editor)
        self._editor = editor

    def sizeHint(self):
        return QSize(self._editor.line_number_area_width(), 0)

    def paintEvent(self, event):
        self._editor._line_number_area_paint_event(event)


class YaraTextEdit(QPlainTextEdit):
    """QPlainTextEdit with built-in line numbers, current-line highlighting, and cursor info."""

    cursor_info_changed = Signal(str)  # "Line: X, Column: Y"
    language_status = Signal(str)
    large_file_mode_changed = Signal(bool)
    formatting_changed = Signal(bool)
    vim_mode_changed = Signal(str)     # vim mode display string

    def __init__(self, parent=None):
        super().__init__(parent)

        self._theme_manager = None
        self.word_wrap_enabled = False

        # --- Vim handler ---
        self._vim_handler = VimHandler(self, parent=self)
        self._vim_handler.mode_changed.connect(self.vim_mode_changed.emit)

        # --- Autocompletion ---
        self._completion_popup = CompletionPopup(self)
        self._completion_popup.completion_selected.connect(self._insert_completion)
        self._completion_timer = QTimer(self)
        self._completion_timer.setSingleShot(True)
        self._completion_timer.setInterval(400)
        self._completion_timer.timeout.connect(lambda: self._trigger_completion(force=False))

        self._backend = EditorBackend(self)
        self._backend.finished.connect(self._on_backend_reply)
        self._source_path = ""
        self._document_epoch = 0
        self._edit_revision = 0
        self._automatic_enabled = True
        self._format_id = -1
        self._format_text = ""
        self._analysis_id = -1
        self._hover_id = -1
        self._last_completion_id = -1
        self._completion_snapshot = None
        self._completion_explicit = False
        self._completion_popup.dismissed.connect(self._dismiss_completion)
        self._diagnostics: list = []
        self._analysis_timer = QTimer(self)
        self._analysis_timer.setSingleShot(True)
        self._analysis_timer.setInterval(300)
        self._analysis_timer.timeout.connect(self.check_rule)

        # --- Snippet tabstop navigation ---
        # Each entry: (start_pos, end_pos) in document coordinates
        self._snippet_tabstops: list[tuple[int, int]] = []
        self._snippet_index: int = -1

        # --- Scrollbar / editor optimizations ---
        document = self.document()
        document.setDocumentMargin(4)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        vsb = self.verticalScrollBar()
        if vsb:
            vsb.setSingleStep(3)
            vsb.setPageStep(20)
            vsb.setTracking(True)
            vsb.setEnabled(True)
            vsb.show()
            vsb.setMouseTracking(True)

        hsb = self.horizontalScrollBar()
        if hsb:
            hsb.setSingleStep(10)
            hsb.setPageStep(50)
            hsb.setTracking(True)

        # Apply default scrollbar style (will be refreshed on theme set)
        self._apply_scrollbar_style()

        # --- Cursor ---
        self.setCursorWidth(2)
        self.ensureCursorVisible()
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextEditorInteraction)

        # --- Line number area ---
        self.line_number_area = _LineNumberArea(self)

        # Connect signals
        self.updateRequest.connect(lambda *_: self.line_number_area.update())
        self.document().contentsChange.connect(self._update_snippet_positions)
        self.textChanged.connect(self._language_changed)
        self.textChanged.connect(self._clear_stale_diagnostics)
        self.textChanged.connect(self._dismiss_completion)
        self.cursorPositionChanged.connect(self._dismiss_completion)
        self.cursorPositionChanged.connect(self._validate_snippet_cursor)
        self.verticalScrollBar().valueChanged.connect(self._dismiss_completion)
        self.horizontalScrollBar().valueChanged.connect(self._dismiss_completion)
        self.textChanged.connect(self._update_line_number_area_width)
        self.textChanged.connect(lambda: self.line_number_area.update())
        self.verticalScrollBar().valueChanged.connect(lambda: self.line_number_area.update())
        self.horizontalScrollBar().valueChanged.connect(lambda: self.line_number_area.update())
        self.cursorPositionChanged.connect(self._highlight_current_line)
        self.cursorPositionChanged.connect(self._show_line_column)
        self.cursorPositionChanged.connect(lambda: self.line_number_area.update())

        # Palette changes (theme switching)
        QApplication.instance().paletteChanged.connect(self._on_font_or_theme_change)

        # Document layout changes for word-wrap responsiveness
        if hasattr(self.document(), 'documentLayoutChanged'):
            self.document().documentLayoutChanged.connect(self._responsive_update)

        # Initial setup
        self._update_line_number_area_width()
        self._highlight_current_line()
        self._show_line_column()

    # ─── Public API ──────────────────────────────────────────────────────

    def set_theme_manager(self, theme_manager):
        """Provide the theme manager for colour lookups."""
        self._theme_manager = theme_manager
        self._completion_popup.set_theme_manager(theme_manager)
        self._apply_scrollbar_style()
        self._highlight_current_line()
        self.line_number_area.update()

    def set_vim_mode(self, enabled: bool):
        """Enable or disable vim-style keybindings."""
        if enabled:
            self._vim_handler.enable()
        else:
            self._vim_handler.disable()

    def set_source_path(self, path):
        self._source_path = path
        self._document_epoch += 1
        self._dismiss_completion()
        self._clear_stale_diagnostics()
        self._language_changed()

    def _compile_options(self):
        # Preserve include support and keep included-file diagnostics separate.
        return CompileOptions(allow_includes=True, origin=self._source_path or None)

    def _document_state(self):
        return (self._edit_revision, self._document_epoch)

    def _language_changed(self):
        self._edit_revision += 1
        self._analysis_id = self._hover_id = -1
        self._analysis_timer.stop()
        enabled = automatic_document_allowed(self.document())
        changed = enabled != self._automatic_enabled
        self._automatic_enabled = enabled
        if enabled:
            self._analysis_timer.start()
        else:
            self._backend.discard_pending_language()
            self._dismiss_completion()
            self._snippet_clear()
            QToolTip.hideText()
        if changed:
            self.large_file_mode_changed.emit(not enabled)
            self.language_status.emit(
                "Automatic editor features resumed" if enabled else
                "Large file (>64 KiB): automatic highlighting, checks, suggestions and smart typing paused. "
                "Manual format/check limit: 256 KiB.")

    @property
    def large_file_mode(self):
        return not self._automatic_enabled

    def check_rule(self):
        self._analysis_timer.stop()
        try:
            self._analysis_id = self._backend.request("analyze", self.toPlainText(),
                self._document_state(), options=self._compile_options())
        except ValueError as exc:
            self.language_status.emit(str(exc))

    @property
    def formatting(self):
        return self._format_id >= 0

    def format_rule(self):
        if self.formatting:
            return
        text = self.toPlainText()
        if not text.strip():
            self.language_status.emit("No YARA rule to format")
            return
        self._dismiss_completion()
        try:
            self._format_id = self._backend.request("format", text, self._document_state(),
                options=self._compile_options())
        except ValueError as exc:
            self.language_status.emit(str(exc))
            return
        if self.formatting:
            self._format_text = text
            self.formatting_changed.emit(True)
            self.language_status.emit("Formatting…")

    def _on_backend_reply(self, reply):
        if reply.kind == "format":
            if reply.request_id != self._format_id:
                return
            self._format_id = -1
            self.formatting_changed.emit(False)
            if reply.state != self._document_state() or self.toPlainText() != self._format_text:
                return
            if reply.error:
                self.language_status.emit(reply.error)
                return
            self._snippet_clear()
            cursor = self.textCursor()
            position, anchor = cursor.position(), cursor.anchor()
            cursor.beginEditBlock()
            cursor.select(QTextCursor.SelectionType.Document)
            cursor.insertText(reply.value)
            cursor.endEditBlock()
            end = self.document().characterCount() - 1
            cursor.setPosition(min(anchor, end))
            cursor.setPosition(min(position, end), QTextCursor.MoveMode.KeepAnchor)
            self.setTextCursor(cursor)
            self.language_status.emit("Formatted with YARA-X Editor Toolkit")
        elif reply.kind == "analyze":
            if reply.request_id != self._analysis_id or reply.state != self._document_state():
                return
            if reply.error:
                self.language_status.emit(reply.error)
            else:
                self.set_diagnostics(reply.value["diagnostics"])
                if not self.formatting:
                    self.language_status.emit("Valid YARA-X rule" if reply.value["valid"] else
                        "\n".join(d["message"] for d in reply.value["diagnostics"]))
        elif reply.kind == "complete":
            if not self._completion_is_current(reply.request_id):
                return
            if reply.error:
                self._dismiss_completion()
                self.language_status.emit(reply.error)
                return
            text = self.toPlainText()
            mapping = SourceMap(text)
            items = [CompletionItem(label=i.label, insert_text=i.edit.text, kind=i.kind,
                detail=i.detail, documentation=i.documentation, snippet=i.snippet,
                replacement=(mapping.utf16[i.edit.span.start], mapping.utf16[i.edit.span.end]))
                for i in reply.value["items"]]
            if items:
                self._completion_popup.show_completions(items, "", self._completion_explicit)
            else:
                self._dismiss_completion()
            signature = reply.value["signature"]
            if signature:
                self.language_status.emit(" | ".join(signature.signatures) + f" — argument {signature.active_parameter + 1}")
        elif reply.kind == "hover":
            if (reply.request_id == self._hover_id and reply.state == self._completion_state()
                    and reply.value is not None and self.isVisible()):
                import html
                item = reply.value
                QToolTip.showText(self._hover_position,
                    html.escape(item.title + "\n" + item.documentation).replace("\n", "<br>"), self)

    def shutdown_backend(self):
        self._analysis_timer.stop()
        self._dismiss_completion()
        self._backend.close()

    def _dismiss_completion(self, *_args):
        self._completion_timer.stop()
        self._last_completion_id = -1
        self._completion_snapshot = None
        self._completion_popup.hide()

    def _completion_state(self):
        cursor = self.textCursor()
        return (self._document_state(), cursor.position(), cursor.anchor())

    def _completion_is_current(self, request_id):
        return (request_id == self._last_completion_id and request_id >= 0
                and self._completion_snapshot == self._completion_state()
                and self.hasFocus() and self.isVisible()
                and (not self._vim_handler.is_enabled() or self._vim_handler._mode == VimMode.INSERT))

    def _completion_text_position(self):
        text = self.toPlainText()
        # QTextCursor positions are UTF-16 units, while Python indexes code points.
        pos = len(text.encode("utf-16-le")[:self.textCursor().position() * 2].decode("utf-16-le"))
        return text, pos

    def focusOutEvent(self, event):
        self._dismiss_completion()
        super().focusOutEvent(event)

    def hideEvent(self, event):
        self._dismiss_completion()
        super().hideEvent(event)

    def mousePressEvent(self, event):
        self._dismiss_completion()
        self._snippet_clear()
        super().mousePressEvent(event)

    def event(self, ev):
        """Show diagnostic tooltip on hover."""
        if ev.type() == QEvent.Type.ToolTip:
            pos = self.cursorForPosition(ev.pos()).position()
            doc = self.document()
            for diag in self._diagnostics:
                if "range" not in diag:
                    continue
                rng = diag["range"]
                s = rng.get("start", {})
                e = rng.get("end", {})
                s_block = doc.findBlockByNumber(s.get("line", 0))
                e_block = doc.findBlockByNumber(e.get("line", 0))
                if not s_block.isValid():
                    continue
                start_pos = s_block.position() + s.get("character", 0)
                end_pos = (e_block.position() + e.get("character", 0)
                           if e_block.isValid()
                           else s_block.position() + s_block.length())
                if start_pos <= pos <= end_pos:
                    QToolTip.showText(ev.globalPos(), diag.get("message", ""))
                    return True
            QToolTip.hideText()
            if self._automatic_enabled:
                text = self.toPlainText()
                cursor = self.cursorForPosition(ev.pos())
                mapping = SourceMap(text)
                offset = mapping.offset(cursor.blockNumber(), cursor.positionInBlock())
                self._hover_position = ev.globalPos()
                self._hover_id = self._backend.request("hover", text, self._completion_state(),
                    offset=offset, options=self._compile_options())
            return True
        return super().event(ev)

    def setup_font(self, family: str = "Consolas", size: int = 8):
        """Configure monospace font for the editor."""
        self._zoom_font_size = size
        font = QFont(family, size)
        self.setFont(font)
        fm = self.fontMetrics()
        self.setTabStopDistance(4 * fm.horizontalAdvance(' '))

    def wheelEvent(self, event):
        """Ctrl+Scroll zooms the editor font size."""
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            delta = event.angleDelta().y()
            if delta == 0:
                return super().wheelEvent(event)
            font = self.font()
            cur = font.pointSize() or 12
            new_size = cur + (1 if delta > 0 else -1)
            new_size = max(6, min(72, new_size))
            if new_size != cur:
                font.setPointSize(new_size)
                self.setFont(font)
                fm = self.fontMetrics()
                self.setTabStopDistance(4 * fm.horizontalAdvance(' '))
                self._zoom_font_size = new_size
            event.accept()
            return
        super().wheelEvent(event)

    def toggle_word_wrap(self):
        """Toggle word wrap and return the new state (True = enabled)."""
        cursor = self.textCursor()
        cursor_position = cursor.position()

        if self.word_wrap_enabled:
            self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            self.word_wrap_enabled = False
        else:
            self.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
            self.word_wrap_enabled = True

        # Force responsive updates
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)
        doc = self.document()
        doc.setModified(doc.isModified())

        cursor.setPosition(cursor_position)
        self.setTextCursor(cursor)

        def update_seq():
            self.line_number_area.update()
            self.viewport().update()

        update_seq()
        QTimer.singleShot(10, update_seq)
        QTimer.singleShot(50, update_seq)
        QTimer.singleShot(100, self.ensureCursorVisible)

        return self.word_wrap_enabled

    def refresh_word_wrap_display(self):
        """Force refresh of word wrap display and line numbers."""
        doc = self.document()
        doc.setModified(doc.isModified())
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)
        self.line_number_area.update()
        self.viewport().update()
        self.ensureCursorVisible()

    # ─── Scrollbar styling ────────────────────────────────────────────────

    def _apply_scrollbar_style(self):
        """Apply theme-aware scrollbar and border stylesheet."""
        if self._theme_manager and self._theme_manager.current_theme:
            c = self._theme_manager.current_theme.colors
            sb_bg = c.scrollbar_background
            raw_handle = c.scrollbar_handle
            raw_hover = c.scrollbar_handle_hover
            border_color = c.primary
        else:
            sb_bg = "#2d2d2d"
            raw_handle = "#606060"
            raw_hover = "#707070"
            border_color = "#3d3d3d"

        try:
            from yaraxgui.ui.themes import ensure_scrollbar_contrast
            sb_handle, sb_hover = ensure_scrollbar_contrast(sb_bg, raw_handle, raw_hover)
        except ImportError:
            sb_handle, sb_hover = raw_handle, raw_hover

        self.setStyleSheet(f"""
            QPlainTextEdit {{
                border: 1px solid {border_color};
            }}
            QScrollBar:vertical {{
                background-color: {sb_bg};
                width: 14px;
                border: none;
                margin: 0px;
            }}
            QScrollBar:horizontal {{
                background-color: {sb_bg};
                height: 14px;
                border: none;
                margin: 0px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {sb_handle};
                min-height: 28px;
                border-radius: 4px;
                margin: 2px 3px 2px 3px;
            }}
            QScrollBar::handle:horizontal {{
                background-color: {sb_handle};
                min-width: 28px;
                border-radius: 4px;
                margin: 3px 2px 3px 2px;
            }}
            QScrollBar::handle:vertical:hover,
            QScrollBar::handle:horizontal:hover {{
                background-color: {sb_hover};
            }}
            QScrollBar::handle:vertical:pressed,
            QScrollBar::handle:horizontal:pressed {{
                background-color: {sb_hover};
            }}
            QScrollBar::add-line, QScrollBar::sub-line {{
                width: 0px;
                height: 0px;
                background: none;
                border: none;
            }}
            QScrollBar::add-page, QScrollBar::sub-page {{
                background: none;
            }}
        """)

    # ─── Line number area ────────────────────────────────────────────────

    def line_number_area_width(self) -> int:
        digits = 1
        count = max(1, self.document().blockCount())
        while count >= 10:
            count //= 10
            digits += 1

        number_font = QFont(self.font())
        number_font.setBold(True)
        from PySide6.QtGui import QFontMetrics
        fm = QFontMetrics(number_font, self.line_number_area)
        digit_width = max(fm.horizontalAdvance(str(digit)) for digit in range(10))
        base_padding = 12
        font_size_padding = max(4, fm.height() // 4)
        left_padding = base_padding + font_size_padding
        right_padding = 8 + font_size_padding // 2
        return left_padding + (digit_width * digits) + right_padding

    def _update_line_number_area_width(self):
        width = self.line_number_area_width()
        self.setViewportMargins(width, 0, 0, 0)
        cr = self.contentsRect()
        self.line_number_area.setGeometry(QRect(cr.left(), cr.top(), width, cr.height()))

    def _highlight_current_line(self):
        """Update all extra selections: current-line + diagnostics."""
        extra_selections = []

        # Current-line highlight
        if not self.isReadOnly():
            selection = QTextEdit.ExtraSelection()
            if self._theme_manager and self._theme_manager.current_theme:
                line_color = QColor(self._theme_manager.current_theme.colors.editor_current_line)
            else:
                line_color = QColor(250, 250, 250)
            selection.format.setBackground(line_color)
            selection.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
            selection.cursor = self.textCursor()
            selection.cursor.clearSelection()
            extra_selections.append(selection)

        # Diagnostic underlines
        doc = self.document()
        for diag in self._diagnostics:
            if "range" not in diag:
                continue
            rng = diag.get("range", {})
            start = rng.get("start", {})
            end = rng.get("end", {})
            severity = diag.get("severity", 1)

            start_block = doc.findBlockByNumber(start.get("line", 0))
            end_block = doc.findBlockByNumber(end.get("line", 0))
            if not start_block.isValid():
                continue

            cursor = QTextCursor(doc)
            start_pos = start_block.position() + min(max(0, start.get("character", 0)), start_block.length() - 1)
            end_pos = (end_block.position() + min(max(0, end.get("character", 0)), end_block.length() - 1)
                       if end_block.isValid() else start_block.position() + start_block.length() - 1)
            if end_pos < start_pos:
                continue
            cursor.setPosition(start_pos)
            cursor.setPosition(end_pos, QTextCursor.MoveMode.KeepAnchor)

            sel = QTextEdit.ExtraSelection()
            fmt = QTextCharFormat()
            fmt.setUnderlineStyle(QTextCharFormat.UnderlineStyle.WaveUnderline)
            if severity <= 1:
                fmt.setUnderlineColor(QColor("#ff4444"))
            elif severity == 2:
                fmt.setUnderlineColor(QColor("#ffaa00"))
            else:
                fmt.setUnderlineColor(QColor("#4488ff"))
            sel.format = fmt
            sel.cursor = cursor
            extra_selections.append(sel)

        self.setExtraSelections(extra_selections)

    def _clear_stale_diagnostics(self):
        if self._diagnostics:
            self._diagnostics = []
            QToolTip.hideText()
            self._highlight_current_line()

    def set_diagnostics(self, diagnostics: list):
        """Store compiler diagnostics and refresh underlines."""
        self._diagnostics = diagnostics
        self._highlight_current_line()

    def _line_number_area_paint_event(self, event):
        painter = QPainter(self.line_number_area)
        try:
            # --- Determine colors ---
            if self._theme_manager and self._theme_manager.current_theme:
                colors = self._theme_manager.current_theme.colors
                line_bg = QColor(colors.editor_line_number_bg)
                text_color = QColor(colors.editor_line_number_text)
                current_line_color = QColor(colors.editor_current_line)
                current_text_color = QColor(colors.editor_text)
                separator_color = QColor(colors.primary)
            else:
                palette = QApplication.palette()
                bg_color = palette.color(palette.ColorRole.Base)
                if bg_color.lightness() > 128:
                    line_bg = bg_color.darker(105)
                    text_color = palette.color(palette.ColorRole.Text).lighter(150)
                    current_line_color = QColor(240, 240, 240, 120)
                    current_text_color = palette.color(palette.ColorRole.Text)
                else:
                    line_bg = bg_color.lighter(115)
                    text_color = palette.color(palette.ColorRole.Text).darker(150)
                    current_line_color = QColor(80, 80, 80, 120)
                    current_text_color = palette.color(palette.ColorRole.Text)
                separator_color = text_color

            painter.fillRect(event.rect(), line_bg)

            doc = self.document()
            width = self.line_number_area.width()
            current_cursor_line = self.textCursor().blockNumber()

            # Prepare bold font for current line number
            original_font = self.font()
            painter.setFont(original_font)
            bold_font = QFont(original_font)
            bold_font.setBold(True)

            viewport_bottom = self.viewport().height()
            block = self.firstVisibleBlock()
            block_number = block.blockNumber()
            y_position = self.blockBoundingGeometry(block).translated(self.contentOffset()).top()

            while block.isValid():
                if block.isVisible():
                    block_height = self.blockBoundingRect(block).height()

                    if y_position + block_height >= 0 and y_position <= viewport_bottom:
                        adjusted_y = y_position

                        if (adjusted_y + block_height >= event.rect().top() and
                                adjusted_y <= event.rect().bottom()):

                            if block_number == current_cursor_line:
                                painter.fillRect(0, adjusted_y, width, block_height, current_line_color)
                                painter.setPen(current_text_color)
                                painter.setFont(bold_font)
                            else:
                                painter.setPen(text_color)
                                painter.setFont(original_font)

                            number = str(block_number + 1)
                            right_margin = max(5, width // 10)
                            layout = block.layout()
                            first_line = layout.lineAt(0)
                            baseline = adjusted_y + first_line.y() + first_line.ascent()
                            painter.drawText(QPointF(
                                width - right_margin - painter.fontMetrics().horizontalAdvance(number),
                                baseline), number)

                            if (self.word_wrap_enabled and block.layout() and block.layout().lineCount() > 1):
                                painter.setFont(original_font)
                                painter.setPen(text_color.darker(150))
                                layout = block.layout()
                                for vi in range(1, layout.lineCount()):
                                    line = layout.lineAt(vi)
                                    cy = adjusted_y + line.y()
                                    if cy < adjusted_y + block_height:
                                        painter.drawText(QPointF(
                                            width - right_margin - painter.fontMetrics().horizontalAdvance("\u2219"),
                                            cy + line.ascent()), "\u2219")

                    y_position += block_height
                    if y_position > viewport_bottom:
                        break

                block = block.next()
                block_number += 1

            # Restore font, then draw separator line
            painter.setFont(original_font)
            pen = QPen(separator_color, 1)
            painter.setPen(pen)
            painter.drawLine(width - 1, event.rect().top(), width - 1, event.rect().bottom())
        finally:
            painter.end()

    def _show_line_column(self):
        cursor = self.textCursor()
        logical_line = cursor.blockNumber() + 1
        col = cursor.columnNumber() + 1

        if self.word_wrap_enabled:
            try:
                block = cursor.block()
                if block.isValid() and block.layout():
                    layout = block.layout()
                    relative_pos = cursor.positionInBlock()
                    visual_line_in_block = layout.lineForTextPosition(relative_pos).lineNumber()

                    self.cursor_info_changed.emit(
                        f"Line: {logical_line}, Column: {col} (wrapped row {visual_line_in_block + 1})")
                else:
                    self.cursor_info_changed.emit(f"Line: {logical_line}, Column: {col}")
            except Exception:
                self.cursor_info_changed.emit(f"Line: {logical_line}, Column: {col}")
        else:
            self.cursor_info_changed.emit(f"Line: {logical_line}, Column: {col}")

    # ─── Overrides ───────────────────────────────────────────────────────

    # ─── Auto-pair / auto-indent constants ──────────────────────────────

    _OPEN_PAIRS = {"(": ")", "[": "]", "{": "}"}
    _CLOSE_CHARS = {")", "]", "}"}
    _QUOTE_CHARS = {'"'}
    _PAIR_MAP = {"(": ")", "[": "]", "{": "}", '"': '"'}

    def insertFromMimeData(self, source):
        if source.hasText() and self._replace_snippet_input(source.text()):
            return
        """Always paste as plain text, stripping any rich-text formatting."""
        if source.hasText():
            plain = QMimeData()
            plain.setText(source.text())
            super().insertFromMimeData(plain)
        else:
            super().insertFromMimeData(source)

    def keyPressEvent(self, event):
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier and event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
            if event.key() == Qt.Key.Key_F:
                self.format_rule()
                return
            if event.key() == Qt.Key.Key_L:
                self.check_rule()
                return
        was_visible = self._completion_popup.isVisible()
        if event.key() == Qt.Key.Key_Escape and not was_visible:
            self._dismiss_completion()
        # 1. Completion popup consumes navigation/accept keys when visible
        if self._completion_popup.handle_key(event):
            return

        # 1b. Snippet tabstop navigation: Tab / Shift+Tab
        if self._snippet_tabstops:
            if event.key() == Qt.Key.Key_Tab and not event.modifiers():
                self._snippet_next()
                return
            if (event.key() == Qt.Key.Key_Backtab
                    or (event.key() == Qt.Key.Key_Tab
                        and event.modifiers() & Qt.KeyboardModifier.ShiftModifier)):
                self._snippet_prev()
                return
            if event.key() == Qt.Key.Key_Escape:
                self._snippet_clear()
                return
            # Any other typing exits snippet mode after the current tabstop
            if event.text() and event.text().isprintable():
                # Let the keypress through, then clear snippet after this stop
                pass  # will be handled by normal typing

        if self._snippet_tabstops and not (event.modifiers() & (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier | Qt.KeyboardModifier.MetaModifier)):
            if event.key() in (Qt.Key.Key_Backspace, Qt.Key.Key_Delete):
                if self._replace_snippet_input("", -1 if event.key() == Qt.Key.Key_Backspace else 1):
                    return
            elif event.text() and event.text().isprintable():
                if self._replace_snippet_input(event.text()):
                    return

        # 2. Vim handler
        if self._vim_handler.is_enabled():
            if self._vim_handler.handle_key_event(event):
                return

        # 3. Ctrl+Space → manual completion trigger
        if (event.key() == Qt.Key.Key_Space and
                event.modifiers() & Qt.KeyboardModifier.ControlModifier):
            self._trigger_completion(force=True)
            return

        # Large files use Qt's plain typing path. In particular, avoid whole-
        # document lexing and Unicode maps for pairing, indentation or completion.
        if self.large_file_mode:
            super().keyPressEvent(event)
            return

        # 4. "." after module name → insert then trigger immediately
        if event.text() == ".":
            super().keyPressEvent(event)
            self._trigger_completion(force=False)
            return

        ch = event.text()
        cursor = self.textCursor()
        has_sel = cursor.hasSelection()
        text, pos = self._completion_text_position()
        noncode = self._cursor_in_noncode_context(text, pos)
        next_char = text[pos] if pos < len(text) else ""

        # 5. Enter → smart auto-indent
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and not event.modifiers():
            self._handle_enter(cursor, text, pos)
            return

        # 6. Skip-over closing bracket / quote
        if ch in self._CLOSE_CHARS and not has_sel and next_char == ch and not noncode:
            cursor.movePosition(QTextCursor.MoveOperation.Right)
            self.setTextCursor(cursor)
            return

        # 7. Quote smart handling
        if ch in self._QUOTE_CHARS and not has_sel:
            # Skip-over if next char is the same quote
            if (next_char == ch and self._is_inside_string(text, pos)
                    and (len(text[:pos]) - len(text[:pos].rstrip("\\"))) % 2 == 0):
                cursor.movePosition(QTextCursor.MoveOperation.Right)
                self.setTextCursor(cursor)
                return
            # Auto-pair quote (only if not already inside a string)
            if not noncode and not self._is_inside_string(text, pos):
                cursor.beginEditBlock()
                cursor.insertText(ch + ch)
                cursor.movePosition(QTextCursor.MoveOperation.Left)
                cursor.endEditBlock()
                self.setTextCursor(cursor)
                return

        # 8. Auto-close brackets: wrap selection or insert pair
        if ch in self._OPEN_PAIRS and (not noncode or has_sel):
            close = self._OPEN_PAIRS[ch]
            if has_sel:
                # Wrap selection
                sel_text = cursor.selectedText()
                cursor.beginEditBlock()
                cursor.insertText(ch + sel_text + close)
                # Position cursor after the wrapped content
                cursor.movePosition(QTextCursor.MoveOperation.Left)
                cursor.endEditBlock()
                self.setTextCursor(cursor)
            else:
                cursor.beginEditBlock()
                cursor.insertText(ch + close)
                cursor.movePosition(QTextCursor.MoveOperation.Left)
                cursor.endEditBlock()
                self.setTextCursor(cursor)
            if self._automatic_enabled:
                self._completion_timer.start()
            return

        # 9. Backspace → delete matching pair
        if event.key() == Qt.Key.Key_Backspace and not has_sel and pos > 0:
            prev_char = text[pos - 1]
            pair_state = noncode_at(text, pos - 1)
            if (prev_char in self._PAIR_MAP and next_char == self._PAIR_MAP[prev_char]
                    and pair_state is None):
                cursor.beginEditBlock()
                cursor.deletePreviousChar()
                cursor.deleteChar()
                cursor.endEditBlock()
                self.setTextCursor(cursor)
                self._completion_timer.start()
                return

        # 10. Default key handling + debounced completion
        super().keyPressEvent(event)

        if self.large_file_mode:
            return

        # Start debounce timer for typed characters (only in insert mode or vim disabled)
        if ch and (ch.isalnum() or ch in "_$#@!") and not event.modifiers() & (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier | Qt.KeyboardModifier.MetaModifier):
            if self._vim_handler.is_enabled() and self._vim_handler._mode != VimMode.INSERT:
                self._completion_popup.hide()
                return
            if was_visible:
                self._trigger_completion(force=False)
            else:
                self._completion_timer.start()
        elif event.key() in (Qt.Key.Key_Backspace, Qt.Key.Key_Delete):
            if was_visible:
                self._trigger_completion(force=False)
            else:
                self._completion_timer.start()
        else:
            self._dismiss_completion()

    def _handle_enter(self, cursor, text, pos):
        edit, target = newline_edit(text, pos)
        cursor.beginEditBlock()
        cursor.insertText(edit.text)
        cursor.endEditBlock()
        cursor.setPosition(SourceMap(self.toPlainText()).utf16[target])
        self.setTextCursor(cursor)

    def _is_inside_string(self, text, pos):
        token = noncode_at(text, pos)
        return token is not None and token.kind in ("string", "multiline_string")

    def _trigger_completion(self, force=False):
        self._completion_timer.stop()
        if (not self.hasFocus() or not self.isVisible() or self.textCursor().hasSelection()
                or (self._vim_handler.is_enabled() and self._vim_handler._mode != VimMode.INSERT)):
            self._dismiss_completion()
            return
        if not force and self.large_file_mode:
            self._dismiss_completion()
            return
        try:
            # Reject oversized manual requests before building a Unicode map.
            check_source_size(self.toPlainText())
        except ValueError as exc:
            self._dismiss_completion()
            self.language_status.emit(str(exc))
            return
        text, pos = self._completion_text_position()
        self._completion_explicit = force
        self._completion_snapshot = self._completion_state()
        try:
            self._last_completion_id = self._backend.request("complete", text,
                self._completion_snapshot, offset=pos, explicit=force, options=self._compile_options())
        except ValueError as exc:
            self._dismiss_completion()
            self.language_status.emit(str(exc))

    def _cursor_in_noncode_context(self, text, pos):
        return noncode_at(text, pos) is not None

    def _insert_completion(self, insert_text: str, is_snippet: bool, replacement=None):
        """Replace the current prefix with the completion text.

        For toolkit snippets, expands ``${N:placeholder}`` and ``${N}``
        tabstops.  After insertion, the first tabstop is selected and
        Tab / Shift+Tab cycle through the rest.
        """
        self._dismiss_completion()
        self._snippet_clear()
        cursor = self.textCursor()
        text, pos = self._completion_text_position()
        before = text[:pos]

        # Determine prefix length to replace
        word_match = re.search(r'[\$#@!]?\w*$', before)
        prefix_len = len(word_match.group(0)) if word_match else 0

        # Handle import context: also replace the opening quote
        if re.search(r'import\s+"[a-z]*$', before):
            quote_match = re.search(r'"[a-z]*$', before)
            if quote_match:
                prefix_len = len(quote_match.group(0)) - 1  # keep the quote

        # For multi-line snippets, adapt indentation to cursor position
        final_text = insert_text
        if "\n" in final_text:
            line_start = before.rfind("\n") + 1
            line_before = before[line_start:]
            base_indent = ""
            for c in line_before:
                if c in (" ", "\t"):
                    base_indent += c
                else:
                    break
            lines = final_text.split("\n")
            final_text = lines[0] + "\n" + "\n".join(
                base_indent + ln if ln.strip() else ln for ln in lines[1:]
            )

        cursor.beginEditBlock()
        if replacement is not None:
            cursor.setPosition(replacement[0])
            cursor.setPosition(replacement[1], QTextCursor.MoveMode.KeepAnchor)
        else:
            suffix = re.match(r'\w*', text[pos:]).group(0)
            for _ in suffix:
                cursor.deleteChar()
            # Import completions include a quote; consume an already auto-paired quote.
            if final_text.endswith('"') and text[pos + len(suffix):].startswith('"'):
                cursor.deleteChar()
            if '(' in final_text and text[pos + len(suffix):].startswith('()'):
                cursor.deleteChar()
                cursor.deleteChar()
            for _ in range(prefix_len):
                cursor.deletePreviousChar()

        if is_snippet and re.search(r'\$\{?\d', final_text):
            self._snippet_inserting = True
            try:
                self._insert_snippet(cursor, final_text)
            finally:
                cursor.endEditBlock()
                self._snippet_inserting = False
            # Don't override cursor — _insert_snippet already positioned it
        else:
            cursor.insertText(final_text)
            cursor.endEditBlock()
            if final_text.endswith("()"):
                cursor.movePosition(QTextCursor.MoveOperation.Left)
            self.setTextCursor(cursor)

    # ── Snippet tabstop engine ───────────────────────────────────

    def _insert_snippet(self, cursor: QTextCursor, snippet: str):
        """Parse snippet tabstops, insert plain text, and activate navigation."""
        expanded = expand_snippet(snippet)
        insert_start = cursor.selectionStart()
        cursor.insertText(expanded.text)
        mapping = SourceMap(expanded.text)
        self._snippet_numbers = sorted(expanded.tabstops, key=lambda n: (n == 0, n))
        self._snippet_groups = {n: [(insert_start + mapping.utf16[s.start], insert_start + mapping.utf16[s.end])
                                   for s in spans] for n, spans in expanded.tabstops.items()}
        self._snippet_tabstops = [self._snippet_groups[n][0] for n in self._snippet_numbers]
        self._snippet_index = -1

        if self._snippet_tabstops:
            self._snippet_next()

    def _replace_snippet_input(self, inserted, delete=0):
        if self.large_file_mode:
            self._snippet_clear()
            return False
        if not self._snippet_tabstops or self._snippet_index < 0:
            return False
        from bisect import bisect_left
        text = self.toPlainText()
        mapping = SourceMap(text)
        to_python = lambda position: bisect_left(mapping.utf16, position)
        number = self._snippet_numbers[self._snippet_index]
        groups = self._snippet_groups
        start, end = groups[number][0]
        cursor = self.textCursor()
        left, right = cursor.selectionStart(), cursor.selectionEnd()
        if not start <= left <= right <= end:
            self._snippet_clear()
            return False
        a, b = to_python(left), to_python(right)
        begin, finish = to_python(start), to_python(end)
        if a == b and delete:
            if delete < 0:
                a = max(begin, a - 1)
            else:
                b = min(finish, b + 1)
        value = text[begin:a] + inserted + text[b:finish]
        document = Document(text)
        document.tabstops = {n: tuple(Span(to_python(a), to_python(b)) for a, b in spans)
                             for n, spans in groups.items()}
        document.replace_tabstop(number, value)
        new_mapping = SourceMap(document.text)
        self._snippet_inserting = True
        try:
            cursor.beginEditBlock()
            for a16, b16 in reversed(groups[number]):
                cursor.setPosition(a16)
                cursor.setPosition(b16, QTextCursor.MoveMode.KeepAnchor)
                cursor.insertText(value)
            cursor.endEditBlock()
            self._snippet_groups = {n: [(new_mapping.utf16[s.start], new_mapping.utf16[s.end]) for s in spans]
                                    for n, spans in document.tabstops.items()}
            self._snippet_tabstops = [self._snippet_groups[n][0] for n in self._snippet_numbers]
            position = document.tabstops[number][0].start + (a - begin) + len(inserted)
            cursor.setPosition(new_mapping.utf16[position])
            self.setTextCursor(cursor)
        finally:
            self._snippet_inserting = False
        return True

    def _validate_snippet_cursor(self):
        if getattr(self, "_snippet_inserting", False) or not self._snippet_tabstops or self._snippet_index < 0:
            return
        start, end = self._snippet_tabstops[self._snippet_index]
        cursor = self.textCursor()
        if not (start <= cursor.position() <= end and start <= cursor.anchor() <= end):
            self._snippet_clear()

    def _update_snippet_positions(self, position, removed, added):
        # Mirrored typing/paste is handled atomically through Document above.
        # Undo, IME and external edits end the session instead of leaving stale spans.
        if not getattr(self, "_snippet_inserting", False):
            self._snippet_clear()

    def _snippet_next(self):
        """Jump to the next tabstop and select its placeholder."""
        if not self._snippet_tabstops:
            return
        self._snippet_index += 1
        if self._snippet_index >= len(self._snippet_tabstops):
            self._snippet_clear()
            return
        start, end = self._snippet_tabstops[self._snippet_index]
        cursor = self.textCursor()
        cursor.setPosition(start)
        if end > start:
            cursor.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
        self.setTextCursor(cursor)
        # If this is the last tabstop ($0), exit snippet mode
        if self._snippet_numbers[self._snippet_index] == 0:
            self._snippet_clear()

    def _snippet_prev(self):
        """Jump to the previous tabstop."""
        if not self._snippet_tabstops or self._snippet_index <= 0:
            return
        self._snippet_index -= 1
        start, end = self._snippet_tabstops[self._snippet_index]
        cursor = self.textCursor()
        cursor.setPosition(start)
        if end > start:
            cursor.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
        self.setTextCursor(cursor)

    def _snippet_clear(self):
        """Exit snippet mode."""
        self._snippet_tabstops = []
        self._snippet_groups = {}
        self._snippet_numbers = []
        self._snippet_index = -1

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() in (QEvent.Type.FontChange, QEvent.Type.ApplicationFontChange) and hasattr(self, 'line_number_area'):
            self.line_number_area.setFont(self.font())
            self.setTabStopDistance(4 * self.fontMetrics().horizontalAdvance(' '))
            self._update_line_number_area_width()
            self.line_number_area.update()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self.line_number_area.setGeometry(
            QRect(cr.left(), cr.top(), self.line_number_area_width(), cr.height())
        )

    # ─── Internal helpers ────────────────────────────────────────────────

    def _responsive_update(self):
        self._update_line_number_area_width()
        self.line_number_area.update()
        doc = self.document()
        doc.setModified(doc.isModified())

    def _on_font_or_theme_change(self):
        self._update_line_number_area_width()
        self._apply_scrollbar_style()
        self.line_number_area.update()
