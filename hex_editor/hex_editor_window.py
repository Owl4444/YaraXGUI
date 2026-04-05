# -*- coding: utf-8 -*-
"""Main hex editor window — standalone QMainWindow."""

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QFont, QKeySequence, QIcon
from PySide6.QtWidgets import (QMainWindow, QFileDialog, QDockWidget,
                               QStatusBar, QToolBar, QApplication, QLabel)

from .hex_data_buffer import HexDataBuffer
from .hex_widget import HexWidget
from .data_inspector import DataInspectorWidget
from .format_viewer import FormatViewerWidget
from .string_extractor import StringResultsWidget
from .goto_dialog import GotoDialog
from .hex_search import HexSearchDialog


class HexEditorWindow(QMainWindow):
    """Standalone hex editor window."""

    yara_pattern_generated = Signal(str)

    def __init__(self, theme_manager=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Hex Editor")
        self.resize(1200, 800)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)

        # Inherit application icon
        icon_path = Path(__file__).parent.parent / "assets" / "YaraXGUI.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        self._theme_manager = theme_manager
        self._buffer = HexDataBuffer()
        self._search_dialog: HexSearchDialog | None = None

        # ── Central widget ──────────────────────────────────────────

        self._hex_widget = HexWidget(self)
        self.setCentralWidget(self._hex_widget)

        # ── Dock widgets ────────────────────────────────────────────

        # Format viewer (left)
        self._format_viewer = FormatViewerWidget(self)
        self._format_dock = QDockWidget("Format", self)
        self._format_dock.setWidget(self._format_viewer)
        self._format_dock.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self._format_dock)

        # Data inspector (right)
        self._inspector = DataInspectorWidget(self)
        self._inspector.setMinimumWidth(200)
        self._inspector_dock = QDockWidget("Inspector", self)
        self._inspector_dock.setWidget(self._inspector)
        self._inspector_dock.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self._inspector_dock)

        # String results (bottom)
        self._strings_widget = StringResultsWidget(self)
        self._strings_dock = QDockWidget("Strings", self)
        self._strings_dock.setWidget(self._strings_widget)
        self._strings_dock.setAllowedAreas(Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.TopDockWidgetArea)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._strings_dock)
        self._strings_dock.hide()

        # ── Connections ─────────────────────────────────────────────

        self._hex_widget.cursor_moved.connect(self._on_cursor_moved)
        self._format_viewer.navigate_requested.connect(self._hex_widget.navigate_to_offset)
        self._strings_widget.navigate_requested.connect(self._hex_widget.navigate_to_offset)
        self._hex_widget.yara_pattern_requested.connect(self.yara_pattern_generated.emit)

        # ── Menus ───────────────────────────────────────────────────

        self._setup_menus()
        self._setup_toolbar()
        self._setup_statusbar()

        # Apply theme if available
        if self._theme_manager:
            self.apply_theme()

    # ── Menu setup ──────────────────────────────────────────────────

    def _setup_menus(self):
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")
        open_action = QAction("&Open...", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self._on_open)
        file_menu.addAction(open_action)
        file_menu.addSeparator()
        close_action = QAction("&Close", self)
        close_action.setShortcut(QKeySequence("Ctrl+W"))
        close_action.triggered.connect(self.close)
        file_menu.addAction(close_action)

        # Edit menu
        edit_menu = menubar.addMenu("&Edit")
        copy_action = QAction("&Copy", self)
        copy_action.setShortcut(QKeySequence.StandardKey.Copy)
        copy_action.triggered.connect(self._hex_widget.copy_as_hex)
        edit_menu.addAction(copy_action)

        copy_yara_action = QAction("Copy as &YARA Hex", self)
        copy_yara_action.setShortcut(QKeySequence("Ctrl+Y"))
        copy_yara_action.triggered.connect(self._hex_widget.copy_as_yara_hex)
        edit_menu.addAction(copy_yara_action)

        send_yara_action = QAction("&Send to YARA Editor", self)
        send_yara_action.setShortcut(QKeySequence("Ctrl+Shift+Y"))
        send_yara_action.triggered.connect(self._hex_widget.send_to_yara_editor)
        edit_menu.addAction(send_yara_action)

        edit_menu.addSeparator()
        goto_action = QAction("&Go to Offset...", self)
        goto_action.setShortcut(QKeySequence("Ctrl+G"))
        goto_action.triggered.connect(self._on_goto)
        edit_menu.addAction(goto_action)
        find_action = QAction("&Find...", self)
        find_action.setShortcut(QKeySequence.StandardKey.Find)
        find_action.triggered.connect(self._on_find)
        edit_menu.addAction(find_action)

        # View menu
        view_menu = menubar.addMenu("&View")
        view_menu.addAction(self._format_dock.toggleViewAction())
        view_menu.addAction(self._inspector_dock.toggleViewAction())
        view_menu.addAction(self._strings_dock.toggleViewAction())

    def _setup_toolbar(self):
        toolbar = QToolBar("Main", self)
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        open_action = QAction("Open", self)
        open_action.setToolTip("Open file (Ctrl+O)")
        open_action.triggered.connect(self._on_open)
        toolbar.addAction(open_action)

        goto_action = QAction("Goto", self)
        goto_action.setToolTip("Go to offset (Ctrl+G)")
        goto_action.triggered.connect(self._on_goto)
        toolbar.addAction(goto_action)

        find_action = QAction("Find", self)
        find_action.setToolTip("Find pattern (Ctrl+F)")
        find_action.triggered.connect(self._on_find)
        toolbar.addAction(find_action)

        strings_action = QAction("Strings", self)
        strings_action.setToolTip("Toggle strings panel")
        strings_action.triggered.connect(lambda: self._strings_dock.setVisible(not self._strings_dock.isVisible()))
        toolbar.addAction(strings_action)

        inspector_action = QAction("Inspector", self)
        inspector_action.setToolTip("Toggle data inspector")
        inspector_action.triggered.connect(lambda: self._inspector_dock.setVisible(not self._inspector_dock.isVisible()))
        toolbar.addAction(inspector_action)

        format_action = QAction("Format", self)
        format_action.setToolTip("Toggle format viewer")
        format_action.triggered.connect(lambda: self._format_dock.setVisible(not self._format_dock.isVisible()))
        toolbar.addAction(format_action)

    def _setup_statusbar(self):
        self._status_offset = QLabel("Offset: 0x00000000")
        self._status_size = QLabel("Size: 0")
        self._status_format = QLabel("")
        sb = self.statusBar()
        sb.addWidget(self._status_offset)
        sb.addWidget(self._status_size)
        sb.addPermanentWidget(self._status_format)

    # ── Actions ─────────────────────────────────────────────────────

    def _on_open(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "All Files (*)")
        if filepath:
            self.open_file(filepath)

    def _on_goto(self):
        if self._buffer.size() == 0:
            return
        dlg = GotoDialog(self._buffer.size(), self)
        if dlg.exec() == dlg.DialogCode.Accepted:
            self._hex_widget.navigate_to_offset(dlg.result_offset())

    def _on_find(self):
        if self._buffer.size() == 0:
            return
        if self._search_dialog is None:
            self._search_dialog = HexSearchDialog(self._buffer, self)
            self._search_dialog.navigate_requested.connect(self._hex_widget.navigate_to_offset)
        else:
            self._search_dialog.set_buffer(self._buffer)
        self._search_dialog.show()
        self._search_dialog.raise_()
        self._search_dialog.activateWindow()

    def _on_cursor_moved(self, offset: int):
        self._status_offset.setText(f"Offset: 0x{offset:08X} ({offset:,})")
        self._inspector.update_offset(offset)

    # ── Public API ──────────────────────────────────────────────────

    def open_file(self, filepath: str, offset: int = 0, length: int = 0):
        """Open a file in the hex editor, optionally selecting *length* bytes at *offset*."""
        if not self._buffer.open_file(filepath):
            return

        self.setWindowTitle(f"Hex Editor — {Path(filepath).name}")
        self._hex_widget.set_buffer(self._buffer)
        self._inspector.set_buffer(self._buffer)
        self._format_viewer.set_buffer(self._buffer)
        self._strings_widget.set_buffer(self._buffer)

        self._status_size.setText(f"Size: {self._buffer.size():,}")
        self._status_format.setText(self._buffer.format_name)

        if offset > 0 or length > 0:
            self._hex_widget.navigate_to_offset(offset, length)

    def open_bytes(self, data: bytes, name: str = "<memory>", offset: int = 0):
        """Open raw bytes in the hex editor."""
        if not self._buffer.open_bytes(data, name):
            return

        self.setWindowTitle(f"Hex Editor — {name}")
        self._hex_widget.set_buffer(self._buffer)
        self._inspector.set_buffer(self._buffer)
        self._format_viewer.set_buffer(self._buffer)
        self._strings_widget.set_buffer(self._buffer)

        self._status_size.setText(f"Size: {self._buffer.size():,}")
        self._status_format.setText(self._buffer.format_name)

        if offset > 0:
            self._hex_widget.navigate_to_offset(offset)

    # ── Theming ─────────────────────────────────────────────────────

    def apply_theme(self):
        """Apply the current theme from theme_manager."""
        if not self._theme_manager or not self._theme_manager.current_theme:
            return
        theme = self._theme_manager.current_theme
        qss = self._theme_manager.generate_qss_stylesheet(theme)
        self.setStyleSheet(qss)
        self._hex_widget.set_theme(theme.colors)

        # Set monospace font
        font_name = theme.font_family or "Cascadia Code"
        font = QFont(font_name, 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._hex_widget.setFont(font)
