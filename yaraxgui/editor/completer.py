# -*- coding: utf-8 -*-
"""YARA autocompletion engine and popup for YaraTextEdit."""

from dataclasses import dataclass
from typing import List, Optional

from PySide6.QtCore import Qt, Signal, QTimer, QPoint
from PySide6.QtGui import QColor, QFont, QKeyEvent, QTextCursor
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QListWidget,
                               QListWidgetItem, QLabel, QTextEdit,
                               QApplication)


# ── Completion item data ─────────────────────────────────────────

@dataclass
class CompletionItem:
    label: str          # display text
    insert_text: str    # text to insert
    kind: str           # "keyword", "module", "function", "attribute", "variable", "snippet", "meta_key"
    detail: str = ""    # type info / description
    documentation: str = ""
    snippet: bool = False  # True if insert_text contains $0 placeholder
    replacement: Optional[tuple[int, int]] = None  # validated UTF-16 document range

    @property
    def icon(self) -> str:
        icons = {
            "keyword": "\u25b6",   # ▶
            "module": "\u25a0",    # ■
            "function": "\u0192",  # ƒ
            "attribute": "\u25cf", # ●
            "variable": "$",
            "snippet": "\u25b6",   # ▶
            "meta_key": "\u25cf",  # ●
        }
        return icons.get(self.kind, "\u25b6")


class CompletionPopup(QWidget):
    """Frameless popup showing completion items with detail label."""

    dismissed = Signal()
    completion_selected = Signal(str, bool, object)  # insert_text, is_snippet

    MAX_VISIBLE = 10

    def __init__(self, editor: QTextEdit, parent=None):
        super().__init__(parent or editor, Qt.WindowType.ToolTip)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setWindowFlag(Qt.WindowType.WindowDoesNotAcceptFocus, True)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._explicit = False
        self._editor = editor
        self._prefix = ""
        self._items: List[CompletionItem] = []
        self._navigated = False  # True once user presses Up/Down in the list

        layout = QVBoxLayout(self)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.setSpacing(0)

        self._list = QListWidget()
        self._list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._list.currentRowChanged.connect(self._on_row_changed)
        self._list.itemDoubleClicked.connect(self._accept_current)
        self._list.itemClicked.connect(lambda _: setattr(self, "_navigated", True))
        layout.addWidget(self._list)

        self._detail = QLabel()
        self._detail.setWordWrap(True)
        self._detail.setMaximumHeight(150)
        self._detail.setTextFormat(Qt.TextFormat.RichText)
        self._detail.setContentsMargins(6, 4, 6, 4)
        layout.addWidget(self._detail)

        self.setFixedWidth(420)
        self.hide()

    def set_theme_manager(self, theme_manager):
        """Apply theme colours to popup."""
        if not theme_manager or not theme_manager.current_theme:
            return
        c = theme_manager.current_theme.colors
        bg = getattr(c, "surface", getattr(c, "editor_background", "#1e1e1e"))
        text = getattr(c, "text_primary", getattr(c, "editor_text", "#cccccc"))
        sel_bg = getattr(c, "selection_background", "#264f78")
        sel_text = getattr(c, "selection_text", "#ffffff")
        border = getattr(c, "primary", "#3d3d3d")
        self.setStyleSheet(f"""
            CompletionPopup {{
                background: {bg};
                border: 1px solid {border};
            }}
            QListWidget {{
                background: {bg};
                color: {text};
                border: none;
                outline: none;
            }}
            QListWidget::item:selected {{
                background: {sel_bg};
                color: {sel_text};
            }}
            QLabel {{
                color: {text};
                background: {bg};
            }}
        """)

    def show_completions(self, items: List[CompletionItem], prefix: str, explicit: bool = False):
        """Populate and show the popup."""
        preserve = self.isVisible() and self._prefix == prefix and self._navigated
        old_row = self._list.currentRow()
        selected = self._items[old_row].label if preserve and 0 <= old_row < len(self._items) else None
        self._items = items
        self._prefix = prefix
        self._explicit = explicit
        self._navigated = preserve
        self._list.clear()

        if not items:
            self.hide()
            return

        for item in items:
            li = QListWidgetItem(f"{item.icon}  {item.label}")
            li.setData(Qt.ItemDataRole.UserRole, item)
            self._list.addItem(li)

        self._list.setCurrentRow(next((i for i, item in enumerate(items) if item.label == selected), 0))
        row_h = self._list.sizeHintForRow(0) or 20
        visible_rows = min(len(items), self.MAX_VISIBLE)
        self._list.setFixedHeight(row_h * visible_rows + 4)
        self.adjustSize()

        self._position_popup()
        self.show()
        self.raise_()

    def _position_popup(self):
        """Position below cursor, clamped to screen edges."""
        cursor = self._editor.textCursor()
        rect = self._editor.cursorRect(cursor)
        global_pos = self._editor.viewport().mapToGlobal(QPoint(rect.left(), rect.bottom() + 2))

        screen = QApplication.screenAt(global_pos)
        if screen:
            screen_geo = screen.availableGeometry()
            # Clamp horizontal
            if global_pos.x() + self.width() > screen_geo.right():
                global_pos.setX(screen_geo.right() - self.width())
            # Flip above if too low
            if global_pos.y() + self.height() > screen_geo.bottom():
                global_pos.setY(self._editor.viewport().mapToGlobal(
                    QPoint(rect.left(), rect.top())).y() - self.height() - 2)

            global_pos.setX(max(screen_geo.left(), global_pos.x()))
            global_pos.setY(max(screen_geo.top(), global_pos.y()))
        self.move(global_pos)

    def _on_row_changed(self, row: int):
        if 0 <= row < len(self._items):
            item = self._items[row]
            self._detail.setText(self._format_detail(item))
        else:
            self._detail.setText("")

    @staticmethod
    def _format_detail(item: CompletionItem) -> str:
        """Render the detail pane as rich HTML with description + example."""
        import html as _html
        parts = [f"<b>{_html.escape(item.kind)}</b>"]
        if item.detail:
            # Split on " | " — text before is description, after is example
            if " | " in item.detail:
                desc, example = item.detail.split(" | ", 1)
                parts.append(f" &mdash; {_html.escape(desc)}")
                parts.append(
                    f'<br><code style="color:#6a9955;">'
                    f'{_html.escape(example)}</code>')
            else:
                parts.append(f" &mdash; {_html.escape(item.detail)}")
        if item.documentation:
            parts.append("<br>" + _html.escape(item.documentation).replace("\n", "<br>"))
        return "".join(parts)

    def _accept_current(self, *_args):
        row = self._list.currentRow()
        if 0 <= row < len(self._items):
            item = self._items[row]
            self.completion_selected.emit(item.insert_text, item.snippet, item.replacement)
        self.hide()

    def handle_key(self, event: QKeyEvent) -> bool:
        """Handle key events when popup is visible. Returns True if consumed."""
        if not self.isVisible():
            return False

        key = event.key()
        if event.modifiers() & (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier
                                | Qt.KeyboardModifier.MetaModifier | Qt.KeyboardModifier.ShiftModifier):
            self.hide()
            return False

        if key == Qt.Key.Key_Escape:
            self.hide()
            return True

        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            if self._navigated or self._explicit:
                self._accept_current()
                return True
            self.hide()
            return False

        # Tab only accepts if user has explicitly navigated the list
        if key == Qt.Key.Key_Tab:
            if self._navigated or self._explicit:
                self._accept_current()
                return True
            # Otherwise dismiss and let Tab indent normally
            self.hide()
            return False

        if key == Qt.Key.Key_Down:
            row = self._list.currentRow()
            if row < self._list.count() - 1:
                self._list.setCurrentRow(row + 1)
            self._navigated = True
            return True

        if key == Qt.Key.Key_Up:
            row = self._list.currentRow()
            if row > 0:
                self._list.setCurrentRow(row - 1)
            self._navigated = True
            return True

        return False

    def hideEvent(self, event):
        self.dismissed.emit()
        super().hideEvent(event)

    @property
    def is_visible(self) -> bool:
        return self.isVisible()
