# This Python file uses the following encoding: utf-8

"""
YaraTextEdit - QTextEdit subclass with built-in line numbers, current line
highlighting, cursor position reporting, word wrap toggle, monospace font setup,
and optional vim-style keybindings.
"""

import re

from PySide6.QtCore import QRect, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QTextCursor, QTextFormat
from PySide6.QtWidgets import QApplication, QTextEdit, QWidget

from vim_handler import VimHandler, VimMode
from yara_completer import CompletionEngine, CompletionPopup


class _LineNumberArea(QWidget):
    """Widget that paints line numbers alongside the editor."""

    def __init__(self, editor: "YaraTextEdit"):
        super().__init__(editor)
        self._editor = editor

    def sizeHint(self):
        return QSize(self._editor.line_number_area_width(), 0)

    def paintEvent(self, event):
        self._editor._line_number_area_paint_event(event)


class YaraTextEdit(QTextEdit):
    """QTextEdit with built-in line numbers, current-line highlighting, and cursor info."""

    cursor_info_changed = Signal(str)  # "Line: X, Column: Y"
    vim_mode_changed = Signal(str)     # vim mode display string

    def __init__(self, parent=None):
        super().__init__(parent)

        self._theme_manager = None
        self.word_wrap_enabled = False

        # --- Vim handler ---
        self._vim_handler = VimHandler(self, parent=self)
        self._vim_handler.mode_changed.connect(self.vim_mode_changed.emit)

        # --- Autocompletion ---
        self._completion_engine = CompletionEngine()
        self._completion_popup = CompletionPopup(self)
        self._completion_popup.completion_selected.connect(self._insert_completion)
        self._completion_timer = QTimer(self)
        self._completion_timer.setSingleShot(True)
        self._completion_timer.setInterval(400)
        self._completion_timer.timeout.connect(lambda: self._trigger_completion(force=False))

        # --- Scrollbar / editor optimizations ---
        document = self.document()
        document.setDocumentMargin(4)
        self.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
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

    def setup_font(self, family: str = "Consolas", size: int = 8):
        """Configure monospace font for the editor."""
        font = QFont(family, size)
        if not font.exactMatch():
            font = QFont("Courier New", size)
        if not font.exactMatch():
            font = QFont("Monaco", size)
        if not font.exactMatch():
            font = QFont("monospace", size)
        self.setFont(font)

        # Configure tab to 4 spaces
        fm = self.fontMetrics()
        self.setTabStopDistance(4 * fm.horizontalAdvance(' '))

    def toggle_word_wrap(self):
        """Toggle word wrap and return the new state (True = enabled)."""
        cursor = self.textCursor()
        cursor_position = cursor.position()

        if self.word_wrap_enabled:
            self.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
            self.word_wrap_enabled = False
        else:
            self.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
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
            from themes import ensure_scrollbar_contrast
            sb_handle, sb_hover = ensure_scrollbar_contrast(sb_bg, raw_handle, raw_hover)
        except ImportError:
            sb_handle, sb_hover = raw_handle, raw_hover

        self.setStyleSheet(f"""
            QTextEdit {{
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

        fm = self.fontMetrics()
        digit_width = fm.horizontalAdvance('9')
        base_padding = 12
        font_size_padding = max(4, fm.height() // 4)
        left_padding = base_padding + font_size_padding
        right_padding = 8 + font_size_padding // 2
        return left_padding + (digit_width * digits) + right_padding

    def _update_line_number_area_width(self):
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def _highlight_current_line(self):
        extra_selections = []
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
        self.setExtraSelections(extra_selections)

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
            font_height = self.fontMetrics().height()
            current_cursor_line = self.textCursor().blockNumber()

            # Prepare bold font for current line number
            original_font = painter.font()
            bold_font = QFont(original_font)
            bold_font.setBold(True)

            viewport_top = self.verticalScrollBar().value()
            viewport_bottom = viewport_top + self.viewport().height()

            block = doc.firstBlock()
            block_number = 0
            y_position = 0

            while block.isValid():
                if block.isVisible():
                    block_height = int(doc.documentLayout().blockBoundingRect(block).height())

                    if y_position + block_height >= viewport_top and y_position <= viewport_bottom:
                        adjusted_y = y_position - viewport_top

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
                            document_margin = doc.documentMargin()
                            text_top_y = adjusted_y + document_margin

                            painter.drawText(
                                0, int(text_top_y), width - right_margin, font_height,
                                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop, number
                            )

                            if (self.word_wrap_enabled and block.layout() and block.layout().lineCount() > 1):
                                painter.setFont(original_font)
                                painter.setPen(text_color.darker(150))
                                layout = block.layout()
                                for vi in range(1, layout.lineCount()):
                                    line = layout.lineAt(vi)
                                    cy = adjusted_y + line.y() + document_margin
                                    if cy < adjusted_y + block_height + document_margin:
                                        painter.drawText(
                                            0, int(cy), width - right_margin, font_height,
                                            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop, "\u2219"
                                        )

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

                    total_visual_lines = 0
                    current_block = self.document().firstBlock()
                    while current_block.isValid() and current_block.blockNumber() < logical_line - 1:
                        if current_block.layout():
                            total_visual_lines += current_block.layout().lineCount()
                        else:
                            total_visual_lines += 1
                        current_block = current_block.next()

                    visual_line = total_visual_lines + visual_line_in_block + 1
                    self.cursor_info_changed.emit(f"Line: {visual_line} (Block: {logical_line}), Column: {col}")
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

    def keyPressEvent(self, event):
        # 1. Completion popup consumes navigation/accept keys when visible
        if self._completion_popup.handle_key(event):
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

        # 4. "." after module name → insert then trigger immediately
        if event.text() == ".":
            super().keyPressEvent(event)
            QTimer.singleShot(0, lambda: self._trigger_completion(force=True))
            return

        ch = event.text()
        cursor = self.textCursor()
        has_sel = cursor.hasSelection()
        text = self.toPlainText()
        pos = cursor.position()
        next_char = text[pos] if pos < len(text) else ""

        # 5. Enter → smart auto-indent
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and not event.modifiers():
            self._handle_enter(cursor, text, pos)
            return

        # 6. Skip-over closing bracket / quote
        if ch in self._CLOSE_CHARS and not has_sel and next_char == ch:
            cursor.movePosition(QTextCursor.MoveOperation.Right)
            self.setTextCursor(cursor)
            return

        # 7. Quote smart handling
        if ch in self._QUOTE_CHARS and not has_sel:
            # Skip-over if next char is the same quote
            if next_char == ch and self._is_inside_string(text, pos):
                cursor.movePosition(QTextCursor.MoveOperation.Right)
                self.setTextCursor(cursor)
                return
            # Auto-pair quote (only if not already inside a string)
            if not self._is_inside_string(text, pos):
                cursor.beginEditBlock()
                cursor.insertText(ch + ch)
                cursor.movePosition(QTextCursor.MoveOperation.Left)
                cursor.endEditBlock()
                self.setTextCursor(cursor)
                return

        # 8. Auto-close brackets: wrap selection or insert pair
        if ch in self._OPEN_PAIRS:
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
            self._completion_timer.start()
            return

        # 9. Backspace → delete matching pair
        if event.key() == Qt.Key.Key_Backspace and not has_sel and pos > 0:
            prev_char = text[pos - 1]
            if prev_char in self._PAIR_MAP and next_char == self._PAIR_MAP[prev_char]:
                cursor.beginEditBlock()
                cursor.deletePreviousChar()
                cursor.deleteChar()
                cursor.endEditBlock()
                self.setTextCursor(cursor)
                self._completion_timer.start()
                return

        # 10. Default key handling + debounced completion
        super().keyPressEvent(event)

        # Start debounce timer for typed characters (only in insert mode or vim disabled)
        if ch and ch.isprintable():
            if self._vim_handler.is_enabled() and self._vim_handler._mode != VimMode.INSERT:
                self._completion_popup.hide()
                return
            self._completion_timer.start()
        elif event.key() in (Qt.Key.Key_Backspace, Qt.Key.Key_Delete):
            self._completion_timer.start()

    def _handle_enter(self, cursor: QTextCursor, text: str, pos: int):
        """Smart Enter: maintain indent, add extra indent after { or section headers."""
        # Get current line's leading whitespace
        line_start = text.rfind("\n", 0, pos) + 1
        line = text[line_start:pos]
        indent = ""
        for c in line:
            if c in (" ", "\t"):
                indent += c
            else:
                break

        tab = "    "  # 4-space indent
        stripped = line.strip()
        prev_char = text[pos - 1] if pos > 0 else ""
        next_char = text[pos] if pos < len(text) else ""

        # Between { and } → expand to 3 lines
        if prev_char == "{" and next_char == "}":
            cursor.beginEditBlock()
            cursor.insertText("\n" + indent + tab + "\n" + indent)
            cursor.endEditBlock()
            # Position cursor on the middle line
            cursor.movePosition(QTextCursor.MoveOperation.Up)
            cursor.movePosition(QTextCursor.MoveOperation.EndOfLine)
            self.setTextCursor(cursor)
            return

        # After { → indent
        if prev_char == "{":
            cursor.insertText("\n" + indent + tab)
            self.setTextCursor(cursor)
            return

        # After YARA section headers (meta:, strings:, condition:)
        if re.match(r'(meta|strings|condition)\s*:', stripped):
            cursor.insertText("\n" + indent + tab)
            self.setTextCursor(cursor)
            return

        # After "rule ... {" line → indent
        if re.match(r'rule\s+\w+', stripped) and stripped.endswith("{"):
            cursor.insertText("\n" + indent + tab)
            self.setTextCursor(cursor)
            return

        # Default: maintain current indentation
        cursor.insertText("\n" + indent)
        self.setTextCursor(cursor)

    def _is_inside_string(self, text: str, pos: int) -> bool:
        """Rough check: count unescaped quotes before pos on the current line."""
        line_start = text.rfind("\n", 0, pos) + 1
        before = text[line_start:pos]
        count = 0
        i = 0
        while i < len(before):
            if before[i] == '"' and (i == 0 or before[i - 1] != "\\"):
                count += 1
            i += 1
        return count % 2 == 1

    def _trigger_completion(self, force: bool = False):
        """Invoke the completion engine and show popup."""
        # Don't show completions in vim normal/visual modes
        if self._vim_handler.is_enabled() and self._vim_handler._mode != VimMode.INSERT:
            self._completion_popup.hide()
            return

        text = self.toPlainText()
        cursor = self.textCursor()
        pos = cursor.position()

        # ── Suppress in contexts where completions are noise ───────
        if self._cursor_in_noncode_context(text, pos):
            self._completion_popup.hide()
            return

        # Get the current word prefix
        before = text[:pos]
        word_match = re.search(r'[\$#@!]?\w*$', before)
        prefix = word_match.group(0) if word_match else ""

        # Require 3+ chars for automatic popup (reduces noise);
        # 1+ char is fine after "." (module member) or when forced.
        min_chars = 1 if (force or before.endswith(".")) else 3
        if len(prefix) < min_chars:
            self._completion_popup.hide()
            return

        items = self._completion_engine.get_completions(text, pos)

        # Don't show the popup if the only match is an exact match of
        # what's already typed — there's nothing to complete.
        if (len(items) == 1
                and items[0].label.lower() == prefix.lower()
                and items[0].insert_text.rstrip() == prefix):
            self._completion_popup.hide()
            return

        if items:
            self._completion_popup.show_completions(items, prefix)
        else:
            self._completion_popup.hide()

    def _cursor_in_noncode_context(self, text: str, pos: int) -> bool:
        """Return True if cursor is inside a string, hex block, or comment."""
        before = text[:pos]

        # Inside a single-line comment (// ... up to EOL)
        line_start = before.rfind("\n") + 1
        line_before = before[line_start:]
        # Strip strings to avoid matching // inside "http://..."
        stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line_before)
        if "//" in stripped:
            return True

        # Inside a block comment (/* ... */)
        last_open = before.rfind("/*")
        last_close = before.rfind("*/")
        if last_open >= 0 and last_open > last_close:
            return True

        # Inside a quoted string — count unescaped quotes on the line
        if self._is_inside_string(text, pos):
            return True

        # Inside a hex string { ... }
        # Walk backwards to find if we're between { and } in a strings
        # section (not a rule opening brace). Hex strings always follow
        # a pattern like:  $name = { ... }
        last_open_brace = before.rfind("{")
        last_close_brace = before.rfind("}")
        if last_open_brace >= 0 and last_open_brace > last_close_brace:
            # Check if this brace is a hex string (preceded by = on the same logical line)
            pre_brace = before[:last_open_brace].rstrip()
            if pre_brace.endswith("="):
                return True

        return False

    def _insert_completion(self, insert_text: str, is_snippet: bool):
        """Replace the current prefix with the completion text."""
        cursor = self.textCursor()
        text = self.toPlainText()
        pos = cursor.position()
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
            # Current line indent = leading whitespace up to the word being typed
            base_indent = ""
            for c in line_before:
                if c in (" ", "\t"):
                    base_indent += c
                else:
                    break
            # Indent all lines after the first
            lines = final_text.split("\n")
            final_text = lines[0] + "\n" + "\n".join(
                base_indent + ln if ln.strip() else ln for ln in lines[1:]
            )

        cursor.beginEditBlock()
        # Remove prefix
        for _ in range(prefix_len):
            cursor.deletePreviousChar()

        if is_snippet and "$0" in final_text:
            # Split at $0 and position cursor there
            parts = final_text.split("$0", 1)
            cursor.insertText(parts[0])
            snippet_pos = cursor.position()
            cursor.insertText(parts[1])
            cursor.setPosition(snippet_pos)
        else:
            cursor.insertText(final_text)

        cursor.endEditBlock()
        self.setTextCursor(cursor)

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
