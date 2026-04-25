"""Tabbed editor widget — each tab holds a YaraTextEdit with its own highlighter."""

from pathlib import Path

from PySide6.QtCore import Signal, Qt
from PySide6.QtWidgets import QMessageBox, QTabWidget

from yara_editor import YaraTextEdit
from yara_highlighter import YaraHighlighter


class EditorTabWidget(QTabWidget):
    """QTabWidget where every tab is a YaraTextEdit with its own highlighter."""

    current_editor_changed = Signal(object)  # emits the new YaraTextEdit

    def __init__(self, theme_manager=None, parent=None):
        super().__init__(parent)
        self._theme_manager = theme_manager
        self._font_family = "Consolas"
        self._font_size = 12

        self.setTabsClosable(True)
        self.setMovable(True)
        self.tabCloseRequested.connect(self._close_tab)
        self.currentChanged.connect(self._on_current_changed)

    # ── Public API ───────────────────────────────────────────

    def add_editor_tab(
        self,
        text: str = "",
        title: str = "Untitled",
        source_path: str = "",
    ) -> YaraTextEdit:
        """Create a new tab with a fresh editor + highlighter and return the editor."""
        editor = YaraTextEdit(self)

        # Per-tab metadata stored directly on the widget
        editor._tab_source_path = source_path
        editor._tab_modified = False

        # Highlighter
        theme = self._theme_manager.current_theme if self._theme_manager else None
        highlighter = YaraHighlighter(editor.document(), theme=theme)
        editor._tab_highlighter = highlighter

        # Apply current theme / font
        if self._theme_manager:
            editor.set_theme_manager(self._theme_manager)
        editor.setup_font(self._font_family, self._font_size)

        if text:
            editor.setPlainText(text)

        idx = self.addTab(editor, title)
        self.setCurrentIndex(idx)
        return editor

    def current_editor(self) -> YaraTextEdit | None:
        w = self.currentWidget()
        return w if isinstance(w, YaraTextEdit) else None

    def current_highlighter(self) -> YaraHighlighter | None:
        editor = self.current_editor()
        if editor and hasattr(editor, "_tab_highlighter"):
            return editor._tab_highlighter
        return None

    def current_source_path(self) -> str:
        editor = self.current_editor()
        if editor and hasattr(editor, "_tab_source_path"):
            return editor._tab_source_path
        return ""

    def find_tab_by_path(self, path: str) -> int:
        """Return the tab index whose source matches *path*, or -1."""
        try:
            target = str(Path(path).resolve())
        except Exception:
            return -1
        for i in range(self.count()):
            w = self.widget(i)
            if hasattr(w, "_tab_source_path") and w._tab_source_path:
                try:
                    if str(Path(w._tab_source_path).resolve()) == target:
                        return i
                except Exception:
                    continue
        return -1

    # ── Bulk operations (theme / font / vim) ─────────────────

    def update_all_themes(self, theme):
        for i in range(self.count()):
            w = self.widget(i)
            if isinstance(w, YaraTextEdit):
                if self._theme_manager:
                    w.set_theme_manager(self._theme_manager)
                if hasattr(w, "_tab_highlighter"):
                    w._tab_highlighter.update_theme(theme)

    def setup_all_fonts(self, family: str, size: int):
        self._font_family = family
        self._font_size = size
        for i in range(self.count()):
            w = self.widget(i)
            if isinstance(w, YaraTextEdit):
                w.setup_font(family, size)

    def set_all_vim_mode(self, enabled: bool):
        for i in range(self.count()):
            w = self.widget(i)
            if isinstance(w, YaraTextEdit):
                w.set_vim_mode(enabled)

    # ── Internal ─────────────────────────────────────────────

    def _close_tab(self, index: int):
        if self.count() <= 1:
            # Last tab — clear instead of closing
            w = self.widget(0)
            if isinstance(w, YaraTextEdit):
                w.clear()
                w._tab_source_path = ""
                w._tab_modified = False
            self.setTabText(0, "Untitled")
            return
        w = self.widget(index)
        self.removeTab(index)
        if w:
            w.deleteLater()

    def _on_current_changed(self, index: int):
        if index < 0:
            return
        editor = self.current_editor()
        if editor:
            self.current_editor_changed.emit(editor)
