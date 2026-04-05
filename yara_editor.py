# This Python file uses the following encoding: utf-8

"""
YaraTextEdit - QTextEdit subclass with built-in line numbers, current line
highlighting, cursor position reporting, word wrap toggle, monospace font setup,
and optional vim-style keybindings.
"""

from PySide6.QtCore import QRect, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QTextCursor, QTextFormat
from PySide6.QtWidgets import QApplication, QTextEdit, QWidget

from vim_handler import VimHandler


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
            sb_handle = c.scrollbar_handle
            sb_hover = c.scrollbar_handle_hover
            border_color = c.primary
        else:
            sb_bg = "#2d2d2d"
            sb_handle = "#606060"
            sb_hover = "#707070"
            border_color = "#3d3d3d"

        self.setStyleSheet(f"""
            QTextEdit {{
                border: 1px solid {border_color};
            }}
            QScrollBar:vertical {{
                background-color: {sb_bg};
                width: 18px;
                border: none;
            }}
            QScrollBar::handle:vertical {{
                background-color: {sb_handle};
                min-height: 30px;
                border-radius: 9px;
                margin: 2px;
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: {sb_hover};
            }}
            QScrollBar::handle:vertical:pressed {{
                background-color: {sb_hover};
            }}
            QScrollBar::add-line:vertical {{
                height: 0px;
            }}
            QScrollBar::sub-line:vertical {{
                height: 0px;
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

    def keyPressEvent(self, event):
        if self._vim_handler.is_enabled():
            if self._vim_handler.handle_key_event(event):
                return
        super().keyPressEvent(event)

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
