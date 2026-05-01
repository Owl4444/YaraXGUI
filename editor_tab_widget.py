"""Tabbed editor widget — each tab holds a YaraTextEdit with its own highlighter."""

from pathlib import Path

from PySide6.QtCore import Signal, Qt, QTimer
from PySide6.QtWidgets import QMessageBox, QTabWidget

from yara_editor import YaraTextEdit
from yara_highlighter import YaraHighlighter


_next_untitled_id = 0


def _make_uri(source_path: str) -> str:
    """Return an LSP document URI for the given path or a synthetic one."""
    global _next_untitled_id
    if source_path:
        try:
            return Path(source_path).resolve().as_uri()
        except Exception:
            pass
    _next_untitled_id += 1
    return f"untitled:Untitled-{_next_untitled_id}"


class EditorTabWidget(QTabWidget):
    """QTabWidget where every tab is a YaraTextEdit with its own highlighter."""

    current_editor_changed = Signal(object)  # emits the new YaraTextEdit

    def __init__(self, theme_manager=None, parent=None):
        super().__init__(parent)
        self._theme_manager = theme_manager
        self._font_family = "Consolas"
        self._font_size = 12
        self._lsp_client = None

        self.setTabsClosable(True)
        self.setMovable(True)
        self.tabCloseRequested.connect(self._close_tab)
        self.currentChanged.connect(self._on_current_changed)

    # ── LSP integration ─────────────────────────────────────────

    def set_lsp_client(self, client):
        """Set the shared LSP client. Called once from MainWindow."""
        self._lsp_client = client
        if client:
            client.diagnostics_received.connect(self._on_lsp_diagnostics)

    def notify_lsp_open(self, editor: YaraTextEdit):
        """Tell the LSP server about a newly opened document."""
        if not self._lsp_client or not self._lsp_client.is_ready:
            return
        uri = getattr(editor, '_lsp_uri', '')
        if uri:
            self._lsp_client.did_open(uri, editor.toPlainText())

    def notify_all_open(self):
        """Send didOpen for every tab (called when LSP server becomes ready)."""
        for i in range(self.count()):
            w = self.widget(i)
            if isinstance(w, YaraTextEdit):
                # Ensure each editor has the LSP client reference
                if not getattr(w, '_lsp_client', None) and self._lsp_client:
                    w.set_lsp_client(self._lsp_client,
                                    getattr(w, '_lsp_uri', ''))
                    self._setup_lsp_change_debounce(w)
                self.notify_lsp_open(w)

    def _setup_lsp_change_debounce(self, editor: YaraTextEdit):
        """Wire a debounced didChange notification for this editor."""
        timer = QTimer(editor)
        timer.setSingleShot(True)
        timer.setInterval(300)
        editor._lsp_change_timer = timer

        def on_timeout():
            if (self._lsp_client and self._lsp_client.is_ready
                    and hasattr(editor, '_lsp_uri')):
                self._lsp_client.did_change(
                    editor._lsp_uri, editor.toPlainText())

        timer.timeout.connect(on_timeout)
        editor.textChanged.connect(lambda: timer.start())

    def _on_lsp_diagnostics(self, uri: str, diagnostics: list):
        """Route diagnostics from the LSP to the correct editor tab."""
        for i in range(self.count()):
            w = self.widget(i)
            if (isinstance(w, YaraTextEdit)
                    and getattr(w, '_lsp_uri', '') == uri):
                w.set_diagnostics(diagnostics)
                return

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

        # LSP URI
        editor._lsp_uri = _make_uri(source_path)

        # Highlighter
        theme = self._theme_manager.current_theme if self._theme_manager else None
        highlighter = YaraHighlighter(editor.document(), theme=theme)
        editor._tab_highlighter = highlighter

        # Apply current theme / font
        if self._theme_manager:
            editor.set_theme_manager(self._theme_manager)
        editor.setup_font(self._font_family, self._font_size)

        # LSP client
        if self._lsp_client:
            editor.set_lsp_client(self._lsp_client, editor._lsp_uri)
            self._setup_lsp_change_debounce(editor)

        if text:
            editor.setPlainText(text)

        idx = self.addTab(editor, title)
        self.setCurrentIndex(idx)

        # Notify LSP of the new document
        self.notify_lsp_open(editor)

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
        w = self.widget(index)

        # Notify LSP before closing
        if (self._lsp_client and self._lsp_client.is_ready
                and isinstance(w, YaraTextEdit)
                and hasattr(w, '_lsp_uri')):
            self._lsp_client.did_close(w._lsp_uri)

        if self.count() <= 1:
            # Last tab — clear instead of closing
            if isinstance(w, YaraTextEdit):
                w.clear()
                w._tab_source_path = ""
                w._tab_modified = False
                w._diagnostics = []
                w._highlight_current_line()
            self.setTabText(0, "Untitled")
            return
        self.removeTab(index)
        if w:
            w.deleteLater()

    def _on_current_changed(self, index: int):
        if index < 0:
            return
        editor = self.current_editor()
        if editor:
            self.current_editor_changed.emit(editor)
