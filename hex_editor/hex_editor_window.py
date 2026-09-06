# -*- coding: utf-8 -*-
"""Main hex editor window -- standalone QMainWindow.

Refactored to eliminate duplicated buffer distribution across
open_file / open_bytes / _broadcast_buffer_changed by maintaining
a registry of buffer-aware dock widgets.

Design pattern: **Mediator** -- HexEditorWindow coordinates all
dock widgets and the central hex view without them knowing about
each other.
"""

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QAction, QFont, QKeySequence, QIcon
from PySide6.QtWidgets import (QMainWindow, QFileDialog, QDockWidget,
                               QHeaderView, QStatusBar, QToolBar,
                               QToolButton, QMenu, QApplication, QLabel, QWidgetAction,
                               QMessageBox, QSpinBox, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QHBoxLayout, QWidget)

from .hex_data_buffer import HexDataBuffer
from .hex_widget import HexWidget
from .data_inspector import DataInspectorWidget
from .format_viewer import FormatViewerWidget
from .string_extractor import StringResultsWidget
from .entropy_widget import EntropyWidget
from .xor_scanner import XorScannerWidget
from .disasm_widget import DisasmWidget
from .goto_dialog import GotoDialog
from .hex_search import HexSearchDialog
from .transforms import (REGISTRY, TransformError, RecipeStep, find_spec,
                         apply_recipe, recipe_length_preserving)
from .transform_dialog import TransformDialog
from .transform_log import TransformLogWidget, TransformLogEntry
from .binary_diff_window import BinaryDiffWindow
from .edit_log_widget import EditLogWidget


# ── Formatting helpers (pure functions) ────────────────────────────


def _format_scope(scope: str, ranges: list[tuple[int, int]]) -> str:
    if scope == "entire":
        return "Entire file"
    if scope == "selection":
        if not ranges:
            return "Selection"
        lo, hi = ranges[0]
        return f"Selection 0x{lo:X}-0x{hi:X}"
    if not ranges:
        return "Regions"
    if len(ranges) <= 3:
        parts = [f"0x{lo:X}-0x{hi:X}" for lo, hi in ranges]
        return "Regions: " + ", ".join(parts)
    lo0, hi0 = ranges[0]
    return f"Regions: 0x{lo0:X}-0x{hi0:X} \u2026 (+{len(ranges) - 1} more)"


def _format_params(params: dict) -> str:
    if not params:
        return ""
    parts = []
    for k, v in params.items():
        s = str(v) if not isinstance(v, (bytes, bytearray)) else v.hex()
        if len(s) > 32:
            s = s[:29] + "..."
        parts.append(f"{k}={s}")
    return ", ".join(parts)


def _format_recipe_name(steps: list[RecipeStep]) -> str:
    if not steps:
        return "(empty)"
    return " \u2192 ".join(step.spec_name for step in steps)


def _format_recipe_params(steps: list[RecipeStep]) -> str:
    parts = []
    for step in steps:
        if not step.params:
            continue
        parts.append(f"{step.spec_name}: {_format_params(step.params)}")
    return " | ".join(parts)


# ── Dock descriptor (eliminates repetitive dock creation) ──────────


class _DockSpec:
    """Lightweight descriptor for dock widget creation."""
    __slots__ = ("attr", "title", "widget_class", "area", "hidden")

    def __init__(self, attr: str, title: str, widget_class: type,
                 area: Qt.DockWidgetArea, hidden: bool = False):
        self.attr = attr
        self.title = title
        self.widget_class = widget_class
        self.area = area
        self.hidden = hidden


_DOCK_SPECS = [
    _DockSpec("format_viewer", "Format", FormatViewerWidget,
              Qt.DockWidgetArea.LeftDockWidgetArea),
    _DockSpec("inspector", "Inspector", DataInspectorWidget,
              Qt.DockWidgetArea.RightDockWidgetArea),
    _DockSpec("strings_widget", "Strings", StringResultsWidget,
              Qt.DockWidgetArea.BottomDockWidgetArea, hidden=True),
    _DockSpec("entropy_widget", "Entropy", EntropyWidget,
              Qt.DockWidgetArea.BottomDockWidgetArea, hidden=True),
    _DockSpec("xor_widget", "XOR Scanner", XorScannerWidget,
              Qt.DockWidgetArea.BottomDockWidgetArea, hidden=True),
    _DockSpec("disasm_widget", "Disassembly", DisasmWidget,
              Qt.DockWidgetArea.BottomDockWidgetArea, hidden=True),
]


class HexEditorWindow(QMainWindow):
    """Standalone hex editor window.

    Acts as a **Mediator**: coordinates signals between the central
    HexWidget and all dock widgets without them coupling to each other.
    """

    yara_pattern_generated = Signal(str)

    def __init__(self, theme_manager=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Hex Editor")
        self.resize(1200, 800)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)

        # File-list navigation (set via set_file_list before/after open_file)
        self._file_list: list[str] = []
        self._file_index: int = -1

        icon_path = Path(__file__).parent.parent / "assets" / "YaraXGUI.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        self._theme_manager = theme_manager
        self._buffer = HexDataBuffer()
        self._buffer.enable_recovery()
        self._restored_entry = None
        self._recovered_unsaved = False
        self._recovery_error_shown = ''
        self._search_dialog: HexSearchDialog | None = None

        # ── Central widget ──────────────────────────────────────────
        self._hex_widget = HexWidget(self)
        self.setCentralWidget(self._hex_widget)

        # ── Dock widgets (created from specs) ───────────────────────
        self._docks: dict[str, QDockWidget] = {}
        self._widgets: dict[str, QWidget] = {}
        self._buffer_aware: list[QWidget] = []

        for spec in _DOCK_SPECS:
            widget = spec.widget_class(self)
            dock = QDockWidget(spec.title, self)
            dock.setWidget(widget)
            areas = spec.area
            if areas in (Qt.DockWidgetArea.LeftDockWidgetArea,
                         Qt.DockWidgetArea.RightDockWidgetArea):
                dock.setAllowedAreas(
                    Qt.DockWidgetArea.LeftDockWidgetArea |
                    Qt.DockWidgetArea.RightDockWidgetArea)
            else:
                dock.setAllowedAreas(
                    Qt.DockWidgetArea.BottomDockWidgetArea |
                    Qt.DockWidgetArea.TopDockWidgetArea)
            self.addDockWidget(areas, dock)
            if spec.hidden:
                dock.hide()

            self._docks[spec.attr] = dock
            self._widgets[spec.attr] = widget
            if hasattr(widget, "set_buffer"):
                self._buffer_aware.append(widget)

        # Convenience accessors
        self._inspector: DataInspectorWidget = self._widgets["inspector"]
        self._inspector.setMinimumWidth(200)
        self._format_viewer: FormatViewerWidget = self._widgets["format_viewer"]
        self._strings_widget: StringResultsWidget = self._widgets["strings_widget"]
        self._entropy_widget: EntropyWidget = self._widgets["entropy_widget"]
        self._xor_widget: XorScannerWidget = self._widgets["xor_widget"]
        self._disasm_widget: DisasmWidget = self._widgets["disasm_widget"]

        # Transform log (manually created -- has extra signals)
        self._xform_log = TransformLogWidget(self)
        self._xform_dock = QDockWidget("Transforms", self)
        self._xform_dock.setWidget(self._xform_log)
        self._xform_dock.setAllowedAreas(
            Qt.DockWidgetArea.BottomDockWidgetArea |
            Qt.DockWidgetArea.TopDockWidgetArea)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea,
                           self._xform_dock)
        self._xform_dock.hide()
        self._docks["xform_log"] = self._xform_dock

        # Edit log (bottom, hidden until first edit)
        self._edit_log = EditLogWidget(self)
        self._edit_log_dock = QDockWidget("Edit Log", self)
        self._edit_log_dock.setWidget(self._edit_log)
        self._edit_log_dock.setAllowedAreas(
            Qt.DockWidgetArea.BottomDockWidgetArea |
            Qt.DockWidgetArea.TopDockWidgetArea)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea,
                           self._edit_log_dock)
        self._edit_log_dock.hide()
        self._docks["edit_log"] = self._edit_log_dock

        # YARA match hits table (hidden until match data is provided)
        self._match_table = QTableWidget(0, 6, self)
        self._match_table.setHorizontalHeaderLabels(
            ["Rule", "Pattern", "Offset", "Length", "Hex Dump", "ASCII"])
        self._match_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers)
        self._match_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self._match_table.setAlternatingRowColors(True)
        self._match_table.verticalHeader().setVisible(False)
        hdr = self._match_table.horizontalHeader()
        hdr.setStretchLastSection(True)
        for c in range(5):
            hdr.setSectionResizeMode(c, QHeaderView.ResizeMode.Interactive)
        self._match_table.setColumnWidth(0, 140)
        self._match_table.setColumnWidth(1, 100)
        self._match_table.setColumnWidth(2, 90)
        self._match_table.setColumnWidth(3, 50)
        self._match_table.setColumnWidth(4, 250)
        self._match_table.cellClicked.connect(self._on_match_row_clicked)

        self._match_dock = QDockWidget("YARA Matches", self)
        self._match_dock.setWidget(self._match_table)
        self._match_dock.setAllowedAreas(
            Qt.DockWidgetArea.BottomDockWidgetArea
            | Qt.DockWidgetArea.TopDockWidgetArea
            | Qt.DockWidgetArea.RightDockWidgetArea)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea,
                           self._match_dock)
        self._match_dock.hide()  # shown when match data is set
        self._docks["yara_matches"] = self._match_dock

        # ── Signal wiring (Mediator pattern) ────────────────────────
        self._connect_signals()

        # ── Menus & toolbar ─────────────────────────────────────────
        self._setup_menus()
        self._setup_toolbar()
        self._setup_statusbar()
        self._recovery_status = QLabel('')
        self.statusBar().addPermanentWidget(self._recovery_status)
        self._recovery_timer = QTimer(self)
        self._recovery_timer.setInterval(500)
        self._recovery_timer.timeout.connect(self._poll_recovery)
        self._recovery_timer.start()

        if self._theme_manager:
            self.apply_theme()

    # ── Signal wiring ──────────────────────────────────────────────

    def _connect_signals(self):
        hw = self._hex_widget

        # Cursor & selection -> inspector, status, entropy
        hw.cursor_moved.connect(self._on_cursor_moved)
        hw.selection_changed.connect(self._inspector.update_selection)
        hw.cursor_moved.connect(self._entropy_widget.set_cursor_offset)

        # Navigation from dock widgets -> hex view
        for widget in (self._format_viewer, self._strings_widget,
                       self._entropy_widget, self._xor_widget,
                       self._disasm_widget, self._xform_log):
            if hasattr(widget, "navigate_requested"):
                widget.navigate_requested.connect(hw.navigate_to_offset)

        # YARA integration
        hw.yara_pattern_requested.connect(self.yara_pattern_generated.emit)
        hw.pattern_regions_changed.connect(self._on_pattern_regions_changed)

        # Disassembly
        hw.disassemble_requested.connect(self._on_disassemble_requested)

        # Direct byte edits (typing, delete, paste, fill, undo/redo)
        hw.data_edited.connect(self._on_data_edited)

        # Edit log
        self._edit_log.navigate_requested.connect(hw.navigate_to_offset)
        self._edit_log.undo_to_requested.connect(self._on_undo_to_entry)

        # Transforms
        hw.transform_requested.connect(self._on_apply_transform)
        self._xform_log.undo_requested.connect(self._on_undo_transform)
        self._xform_log.redo_requested.connect(self._on_redo_transform)
        self._xform_log.clear_requested.connect(self._on_clear_transforms)
        self._xform_log.modify_requested.connect(self._on_modify_transform)

    # ── Unified buffer distribution ────────────────────────────────

    def _distribute_buffer(self):
        """Push the buffer to every buffer-aware widget. Single source."""
        if self._search_dialog is not None:
            self._search_dialog.set_buffer(self._buffer)
        for widget in self._buffer_aware:
            widget.set_buffer(self._buffer)
        self._hex_widget.set_buffer(self._buffer)
        self._status_size.setText(f"Size: {self._buffer.size():,}")

    def _broadcast_buffer_changed(self):
        """Re-push after transforms (invalidates caches)."""
        if self._search_dialog is not None:
            self._search_dialog.set_buffer(self._buffer)
        for widget in self._buffer_aware:
            widget.set_buffer(self._buffer)
        self._hex_widget.refresh_after_data_change()
        self._status_size.setText(f"Size: {self._buffer.size():,}")

    # ── Menu setup ─────────────────────────────────────────────────

    def _setup_menus(self):
        menubar = self.menuBar()
        hw = self._hex_widget

        # ── File ───────────────────────────────────────────────────
        file_menu = menubar.addMenu("&File")

        open_action = self._open_action = QAction("&Open...", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self._on_open)
        file_menu.addAction(open_action)

        save_as_action = QAction("Save &As...", self)
        save_as_action.setShortcut(QKeySequence("Ctrl+Shift+S"))
        save_as_action.triggered.connect(self._on_save_as)
        file_menu.addAction(save_as_action)

        save_sel_action = QAction("Save Se&lection As...", self)
        save_sel_action.setShortcut(QKeySequence("Ctrl+Shift+E"))
        save_sel_action.setToolTip(
            "Save the current selection (or marked regions) to a new file")
        save_sel_action.triggered.connect(self._on_save_selection_as)
        file_menu.addAction(save_sel_action)

        revert_action = QAction("&Revert (undo all transforms)", self)
        revert_action.triggered.connect(self._on_revert)
        file_menu.addAction(revert_action)

        file_menu.addSeparator()
        close_action = QAction("&Close", self)
        close_action.setShortcut(QKeySequence("Ctrl+W"))
        close_action.triggered.connect(self.close)
        file_menu.addAction(close_action)

        # ── Edit ───────────────────────────────────────────────────
        edit_menu = self._edit_menu = menubar.addMenu("&Edit")

        undo_action = QAction("&Undo", self)
        undo_action.setShortcut(QKeySequence("Ctrl+Z"))
        undo_action.triggered.connect(hw._do_undo)
        edit_menu.addAction(undo_action)

        redo_action = QAction("&Redo", self)
        redo_action.setShortcut(QKeySequence("Ctrl+Shift+Z"))
        redo_action.triggered.connect(hw._do_redo)
        edit_menu.addAction(redo_action)

        edit_menu.addSeparator()

        copy_action = QAction("&Copy", self)
        copy_action.setShortcut(QKeySequence.StandardKey.Copy)
        copy_action.triggered.connect(hw.copy_as_hex)
        edit_menu.addAction(copy_action)

        paste_action = QAction("&Paste", self)
        paste_action.setShortcut(QKeySequence("Ctrl+V"))
        paste_action.triggered.connect(hw._do_paste)
        edit_menu.addAction(paste_action)

        # Copy-as submenu
        copy_as_menu = edit_menu.addMenu("Copy As")
        for label, fmt_name in [
            ("Hex (spaced)", "hex"),
            ("Hex (compact)", "hex_compact"),
            ("YARA Hex\tCtrl+Y", "yara_hex"),
            ("C Escape", "c_escape"),
            ("Python Bytes", "python_bytes"),
            ("ASCII", "ascii"),
            ("Base64", "base64"),
        ]:
            act = copy_as_menu.addAction(label)
            act.triggered.connect(lambda checked, f=fmt_name: hw._exporter.copy(f))
        copy_as_menu.addSeparator()
        act_send = copy_as_menu.addAction("Send to YARA Editor\tCtrl+Shift+Y")
        act_send.triggered.connect(hw.send_to_yara_editor)

        edit_menu.addSeparator()

        insert_action = QAction("&Insert Bytes...", self)
        insert_action.setShortcut(QKeySequence("Ctrl+I"))
        insert_action.triggered.connect(hw._do_insert_dialog)
        edit_menu.addAction(insert_action)

        fill_action = QAction("&Fill Selection...", self)
        fill_action.setShortcut(QKeySequence("Ctrl+Shift+F"))
        fill_action.triggered.connect(hw._do_fill_dialog)
        edit_menu.addAction(fill_action)

        navigate_menu = menubar.addMenu("&Navigate")
        goto_action = self._goto_action = QAction("&Go to Offset...", self)
        goto_action.setShortcut(QKeySequence("Ctrl+G"))
        goto_action.triggered.connect(self._on_goto)

        find_action = self._find_action = QAction("&Find...", self)
        find_action.setShortcut(QKeySequence.StandardKey.Find)
        find_action.triggered.connect(self._on_find)

        navigate_menu.addAction(find_action)
        navigate_menu.addAction(goto_action)
        navigate_menu.addSeparator()
        self._prev_action = QAction("Previous Result File", self)
        self._prev_action.setShortcut("Alt+Left")
        self._prev_action.triggered.connect(self._nav_prev)
        self._prev_action.setEnabled(False)
        self._next_action = QAction("Next Result File", self)
        self._next_action.setShortcut("Alt+Right")
        self._next_action.triggered.connect(self._nav_next)
        self._next_action.setEnabled(False)
        navigate_menu.addAction(self._prev_action)
        navigate_menu.addAction(self._next_action)

        analyze_menu = menubar.addMenu("&Analyze")
        xform_action = QAction("Apply &Transform...", self)
        xform_action.triggered.connect(self._on_apply_transform)
        self._transform_action = xform_action

        diff_action = QAction("&Compare with File... (Binary Diff)", self)
        diff_action.setShortcut(QKeySequence("Ctrl+D"))
        diff_action.setToolTip(
            "Open a side-by-side diff of this file with another file")
        diff_action.triggered.connect(self._on_open_diff)

        analyze_menu.addAction(xform_action)
        analyze_menu.addAction(diff_action)
        analyze_menu.addSeparator()
        entropy_action = analyze_menu.addAction("Entropy Graph")
        entropy_action.triggered.connect(lambda: self._show_panel('entropy_widget'))
        disasm_action = analyze_menu.addAction("Disassembly && CFG")
        disasm_action.triggered.connect(lambda: self._show_panel('disasm_widget'))

        # ── View ───────────────────────────────────────────────────
        view_menu = self._display_menu = menubar.addMenu("&View")

        view_menu.addActions([hw.zoom_in_action, hw.zoom_out_action, hw.zoom_reset_action])
        view_menu.addSeparator()

        self._toggle_view_action = QAction("&Text View", self)
        self._toggle_view_action.setShortcut(QKeySequence("Ctrl+T"))
        self._toggle_view_action.setCheckable(True)
        self._toggle_view_action.setChecked(False)
        self._toggle_view_action.toggled.connect(self._on_toggle_view_mode)
        view_menu.addAction(self._toggle_view_action)

        self._toggle_escape_action = QAction("&Escape non-printable chars", self)
        self._toggle_escape_action.setCheckable(True)
        self._toggle_escape_action.setChecked(False)
        self._toggle_escape_action.setToolTip(
            "Off: notepad view with real newlines. On: fixed grid, dots.")
        self._toggle_escape_action.toggled.connect(self._on_toggle_text_escape_mode)
        view_menu.addAction(self._toggle_escape_action)
        self._toggle_escape_action.setEnabled(False)

        view_menu.addSeparator()

        self._toggle_line_numbers = QAction("&Line Numbers", self)
        self._toggle_line_numbers.setCheckable(True)
        self._toggle_line_numbers.setChecked(False)
        self._toggle_line_numbers.setToolTip(
            "Show line numbers instead of hex offsets in the gutter")
        self._toggle_line_numbers.toggled.connect(self._on_toggle_gutter_mode)
        view_menu.addAction(self._toggle_line_numbers)

        view_menu.addSeparator()

        layout_menu = view_menu.addMenu("Layout")
        row_widget = QWidget()
        row = QHBoxLayout(row_widget)
        row.addWidget(QLabel("Bytes per row:"))
        self._bpl_spin = QSpinBox(row_widget)
        self._bpl_spin.setRange(4, 64)
        self._bpl_spin.setValue(self._hex_widget.bytes_per_line())
        self._bpl_spin.setToolTip("Bytes per row in hex view (4–64).")
        self._bpl_spin.valueChanged.connect(self._hex_widget.set_bytes_per_line)
        self._hex_widget.bytes_per_line_changed.connect(self._on_bpl_changed)
        row.addWidget(self._bpl_spin)
        row_action = QWidgetAction(layout_menu)
        row_action.setDefaultWidget(row_widget)
        layout_menu.addAction(row_action)
        view_menu.addSeparator()

        # Panels submenu — keeps the View menu clean
        panels_menu = view_menu.addMenu("&Panels")
        for dock in self._docks.values():
            panels_menu.addAction(dock.toggleViewAction())

    def _show_panel(self, name):
        self._docks[name].show()
        self._docks[name].raise_()

    def _setup_toolbar(self):
        toolbar = self._main_toolbar = QToolBar("File and analysis", self)
        toolbar.setObjectName("hex_main_toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        # Share QAction instances with menus so shortcuts and state stay in sync.
        for action, label in ((self._open_action, 'Open'), (self._find_action, 'Find'),
                              (self._goto_action, 'Go to'), (self._transform_action, 'Transform')):
            action.setIconText(label)
            toolbar.addAction(action)
        toolbar.addSeparator()
        display = QToolButton(self)
        display.setText("Display")
        display.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        display.setMenu(self._display_menu)
        toolbar.addWidget(display)
        # Aliases preserve the view synchronization hooks, with only one action
        # per option rather than duplicated menu and toolbar toggles.
        self._view_toggle_btn = self._toggle_view_action
        self._escape_text_action = self._toggle_escape_action

        toolbar.addSeparator()
        self._lock_action = QAction("Read-Only", self)
        self._lock_action.setCheckable(True)
        self._lock_action.setChecked(True)
        self._lock_action.setToolTip("Toggle between read-only browsing and byte editing.")
        self._lock_action.toggled.connect(self._on_lock_toggled)
        toolbar.addAction(self._lock_action)
        self._edit_menu.addSeparator()
        self._edit_menu.addAction(self._lock_action)

        self._navigation_toolbar = QToolBar("Result files", self)
        self._navigation_toolbar.setObjectName("hex_result_navigation")
        self._navigation_toolbar.setMovable(False)
        self.addToolBar(self._navigation_toolbar)
        self._prev_action.setIconText('◀ Previous')
        self._next_action.setIconText('Next ▶')
        self._navigation_toolbar.addAction(self._prev_action)
        self._nav_label = QLabel("")
        self._nav_label.setToolTip("Current position in matched files list")
        self._navigation_toolbar.addWidget(self._nav_label)
        self._navigation_toolbar.addAction(self._next_action)
        self._navigation_toolbar.hide()

    def _on_lock_toggled(self, locked: bool):
        self._hex_widget.read_only = locked

    def _on_bpl_changed(self, n: int):
        if self._bpl_spin.value() == n:
            return
        self._bpl_spin.blockSignals(True)
        try:
            self._bpl_spin.setValue(n)
        finally:
            self._bpl_spin.blockSignals(False)

    def _setup_statusbar(self):
        self._status_offset = QLabel("Offset: 0x00000000")
        self._status_size = QLabel("Size: 0")
        self._status_regions = QLabel("")
        self._status_mode = QLabel("Read-Only")
        self._status_mode.setToolTip("Toggle Read-Only in Edit or the toolbar to enable byte editing")
        self._status_format = QLabel("")
        sb = self.statusBar()
        sb.addWidget(self._status_offset)
        sb.addWidget(self._status_size)
        sb.addWidget(self._status_regions)
        sb.addPermanentWidget(self._status_mode)
        sb.addPermanentWidget(self._status_format)

        # Keep status bar in sync with lock state
        self._hex_widget.read_only_changed.connect(self._on_read_only_changed)

    def _on_read_only_changed(self, read_only: bool):
        self._lock_action.blockSignals(True)
        self._lock_action.setChecked(read_only)
        self._lock_action.blockSignals(False)
        self._lock_action.setIconText('Read-Only' if read_only else 'Editable')
        self._lock_action.setToolTip(
            'Enable byte editing' if read_only else 'Return to read-only browsing')
        self._status_mode.setText('Read-Only' if read_only else 'Editable')

    # ── Actions ────────────────────────────────────────────────────

    def _on_open(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "All Files (*)")
        if filepath:
            self.open_file(filepath)

    def _on_open_diff(self):
        """Open a side-by-side binary diff with another file.

        Pre-loads the current file as the left side and prompts for the
        right-side file.
        """
        # Pick the right-side file first so user can cancel cheaply
        right_path, _ = QFileDialog.getOpenFileName(
            self, "Pick file to compare against", "", "All Files (*)")
        if not right_path:
            return
        diff_win = BinaryDiffWindow(theme_manager=self._theme_manager,
                                    parent=None)
        # Keep a reference so it isn't garbage collected
        if not hasattr(self, "_diff_windows"):
            self._diff_windows = []
        self._diff_windows = [w for w in self._diff_windows if w.isVisible()]
        self._diff_windows.append(diff_win)

        # Load left side from the current buffer's file path if available;
        # otherwise prompt for it.
        left_path = self._buffer.filepath if self._buffer else ""
        if left_path and left_path != "<memory>" and Path(left_path).exists():
            diff_win.open_left_file(left_path)
        else:
            picked, _ = QFileDialog.getOpenFileName(
                self, "Pick left-side file", "", "All Files (*)")
            if picked:
                diff_win.open_left_file(picked)
        diff_win.open_right_file(right_path)
        diff_win.show()

    def _on_toggle_view_mode(self, text_mode: bool):
        self._hex_widget.set_text_mode(text_mode)
        self._bpl_spin.setEnabled(not text_mode)
        self._toggle_escape_action.setEnabled(text_mode)
        self._view_toggle_btn.setChecked(text_mode)
        label = "Hex" if text_mode else "Text"
        tooltip = f"Switch to {'hex' if text_mode else 'text'} view (Ctrl+T)"
        self._view_toggle_btn.setText(label)
        self._view_toggle_btn.setToolTip(tooltip)
        self._toggle_view_action.setText("&Hex View" if text_mode else "&Text View")
        # Sync the line-numbers checkbox with the auto-switched gutter mode
        self._toggle_line_numbers.blockSignals(True)
        self._toggle_line_numbers.setChecked(text_mode)
        self._toggle_line_numbers.blockSignals(False)

    def _on_toggle_text_escape_mode(self, escape: bool):
        self._hex_widget.set_text_escape_mode(escape)
        for act in (self._escape_text_action, self._toggle_escape_action):
            if act.isChecked() != escape:
                act.blockSignals(True)
                try:
                    act.setChecked(escape)
                finally:
                    act.blockSignals(False)

    def _on_toggle_gutter_mode(self, line_numbers: bool):
        self._hex_widget.gutter_mode = "line" if line_numbers else "offset"

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
            self._search_dialog.navigate_requested.connect(
                self._hex_widget.navigate_to_offset)
        else:
            self._search_dialog.set_buffer(self._buffer)
        self._search_dialog.show()
        self._search_dialog.raise_()
        self._search_dialog.activateWindow()

    def _on_cursor_moved(self, offset: int):
        self._status_offset.setText(f"Offset: 0x{offset:08X} ({offset:,})")
        self._inspector.update_offset(offset)

    def _on_pattern_regions_changed(self, count: int):
        self._status_regions.setText(
            f"Pattern regions: {count}" if count > 0 else "")

    def _has_unsaved(self):
        return self._buffer.dirty or self._recovered_unsaved

    def _discard_recovery(self):
        self._buffer.discard_recovery()
        if self._restored_entry is not None:
            from yaraxgui.recovery.store import IO_POOL, discard_entry
            IO_POOL.submit(discard_entry, self._restored_entry)
            self._restored_entry = None
        self._recovered_unsaved = False

    def _confirm_replace(self):
        if not self._has_unsaved():
            return True
        answer = QMessageBox.question(self, 'Unsaved hex edits',
            'Save the modified bytes before closing or opening another file?',
            QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard |
            QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Save)
        if answer == QMessageBox.StandardButton.Save:
            return bool(self._on_save_as())
        if answer == QMessageBox.StandardButton.Discard:
            self._discard_recovery()
            return True
        return False

    def _poll_recovery(self):
        journal = self._buffer.recovery
        if journal is None:
            self._recovery_status.setText('')
        elif journal.error:
            self._recovery_status.setText('Recovery unavailable — save your edits')
            if journal.error != self._recovery_error_shown:
                self._recovery_error_shown = journal.error
                QMessageBox.warning(self, 'Recovery unavailable', journal.error)
        elif not journal.ready:
            self._recovery_status.setText('Preparing recovery snapshot…')
        elif journal.saved_sequence < journal.sequence:
            self._recovery_status.setText('Saving recovery edits…')
        else:
            self._recovery_status.setText('Recovery up to date')

    def closeEvent(self, event):
        if not self._confirm_replace():
            event.ignore()
            return
        self._strings_widget.shutdown()
        self._format_viewer.shutdown()
        self._entropy_widget.shutdown()
        self._xor_widget.shutdown()
        if self._search_dialog is not None:
            self._search_dialog.shutdown()
        self._disasm_widget.shutdown()
        self._buffer.close()
        super().closeEvent(event)

    def _on_disassemble_requested(self, code: bytes, base_offset: int):
        self._docks["disasm_widget"].show()
        self._docks["disasm_widget"].raise_()
        self._disasm_widget.disassemble_bytes(code, base_offset)

    def _on_data_edited(self):
        """Handle direct byte edits from the hex widget (typing, delete, etc.)."""
        self._mark_modified()
        self._strings_widget.set_buffer(self._buffer)
        self._entropy_widget.set_buffer(self._buffer)
        if self._search_dialog is not None:
            self._search_dialog.set_buffer(self._buffer)
        self._inspector.set_buffer(self._buffer)
        self._status_size.setText(f"Size: {self._buffer.size():,}")

        # Refresh the edit log table with current-coordinate history
        self._edit_log.set_buffer(self._buffer)
        editor = self._hex_widget._editor
        entries = editor.get_history_view()
        self._edit_log.refresh(entries)
        if entries:
            self._edit_log_dock.show()

    def _on_undo_to_entry(self, target_count: int):
        """Undo back until the undo stack has *target_count* entries."""
        editor = self._hex_widget._editor
        while editor.has_undo() and len(editor.edit_history) > target_count:
            cmd = editor.undo()
            if not cmd:
                break
        self._hex_widget.refresh_after_data_change()
        self._hex_widget._ensure_visible(self._hex_widget._selection.cursor)
        self._hex_widget.data_edited.emit()  # triggers _on_data_edited -> refresh log

    # ── Transform handlers ─────────────────────────────────────────

    def _on_apply_transform(self):
        if self._buffer is None or self._buffer.size() == 0:
            QMessageBox.information(self, "No data", "Open a file first.")
            return

        has_sel = self._hex_widget.has_selection()
        regions = self._hex_widget.pattern_regions()

        PROBE_MAX = 4096
        probe = b""
        probe_size = self._buffer.size()
        if regions:
            lo, hi = regions[0]
            probe_size = hi - lo + 1
            probe = self._buffer.read(lo, min(PROBE_MAX, probe_size))
        elif has_sel:
            sel_lo, sel_hi = self._hex_widget._ordered_selection()
            probe_size = sel_hi - sel_lo + 1
            probe = self._buffer.read(sel_lo, min(PROBE_MAX, probe_size))
        else:
            probe = self._buffer.read(0, PROBE_MAX)

        dlg = TransformDialog(
            has_sel, len(regions), probe_bytes=probe, parent=self,
            probe_complete=probe_size <= PROBE_MAX)
        if dlg.exec() != dlg.DialogCode.Accepted:
            return
        req = dlg.get_request()
        if req is None:
            return

        if req.scope == "selection":
            if not has_sel:
                return
            lo, hi = self._hex_widget._ordered_selection()
            ranges = [(lo, hi)]
        elif req.scope == "regions":
            ranges = sorted(regions)
        else:
            ranges = [(0, self._buffer.size() - 1)]

        if not ranges:
            return

        if not recipe_length_preserving(req.steps) and len(ranges) > 1:
            prev_hi = -1
            for lo, hi in ranges:
                if lo <= prev_hi:
                    QMessageBox.warning(
                        self, "Overlapping ranges",
                        "This recipe changes length and cannot be applied to "
                        "overlapping regions. Please clear or merge regions first.")
                    return
                prev_hi = hi

        # Dry-run: compute transformed output and check for size growth
        if not recipe_length_preserving(req.steps):
            total_orig = 0
            total_new = 0
            preview_results: list[tuple[int, int, bytes]] = []
            try:
                for lo, hi in sorted(ranges):
                    original = self._buffer.read(lo, hi - lo + 1)
                    new_bytes = apply_recipe(original, req.steps)
                    total_orig += len(original)
                    total_new += len(new_bytes)
                    preview_results.append((lo, hi, new_bytes))
            except (TransformError, Exception) as e:
                title = "Transform failed" if isinstance(e, TransformError) else "Transform error"
                msg = str(e) if isinstance(e, TransformError) else f"Unexpected error: {e}"
                QMessageBox.warning(self, title, msg)
                return

            if total_new > total_orig:
                growth = total_new - total_orig
                msg = QMessageBox(self)
                msg.setWindowTitle("Output larger than selection")
                msg.setText(
                    f"The transform output is {total_new:,} bytes "
                    f"({growth:+,} bytes vs. the original {total_orig:,} bytes).\n\n"
                    "Applying in-place will expand the buffer and shift subsequent data. "
                    "You can also save the transformed output to a new file."
                )
                btn_inplace = msg.addButton("Apply In-Place", QMessageBox.ButtonRole.AcceptRole)
                btn_save = msg.addButton("Save to New File", QMessageBox.ButtonRole.ActionRole)
                msg.addButton(QMessageBox.StandardButton.Cancel)
                msg.exec()

                if msg.clickedButton() == btn_save:
                    # Concatenate all transformed ranges and save
                    combined = b"".join(nb for _, _, nb in preview_results)
                    path, _ = QFileDialog.getSaveFileName(
                        self, "Save Transformed Output", "", "All Files (*)")
                    if path:
                        try:
                            with open(path, "wb") as f:
                                f.write(combined)
                            QMessageBox.information(
                                self, "Saved",
                                f"Transformed output saved to:\n{path}")
                        except OSError as e:
                            QMessageBox.warning(
                                self, "Save failed", str(e))
                    return
                elif msg.clickedButton() != btn_inplace:
                    return  # cancelled

        snapshots, new_lengths, applied = self._apply_recipe_to_ranges(
            ranges, req.steps)
        if snapshots is None:
            return

        entry = TransformLogEntry(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            op_name=_format_recipe_name(req.steps),
            scope_label=_format_scope(req.scope, ranges),
            params_label=_format_recipe_params(req.steps),
            snapshots=snapshots,
            new_lengths=new_lengths,
            steps=list(req.steps),
        )
        self._xform_log.add_entry(entry)
        self._xform_dock.show()
        self._mark_modified()
        self._broadcast_buffer_changed()

    def _apply_recipe_to_ranges(self, ranges, steps):
        """Apply recipe to ranges (reverse order). Returns (snapshots, new_lengths, applied) or (None,None,None) on failure."""
        snapshots: list[tuple[int, bytes]] = []
        new_lengths: list[int] = []
        applied: list[tuple[int, int, int]] = []
        try:
            for lo, hi in sorted(ranges, reverse=True):
                original = self._buffer.read(lo, hi - lo + 1)
                new_bytes = apply_recipe(original, steps)
                snapshots.append((lo, original))
                new_lengths.append(len(new_bytes))
                self._buffer.replace_range(lo, hi, new_bytes)
                applied.append((lo, len(original), len(new_bytes)))
        except (TransformError, Exception) as e:
            for (lo, _ol, nl), (_lo2, orig) in zip(
                reversed(applied), reversed(snapshots)
            ):
                self._buffer.replace_range(lo, lo + nl - 1, orig)
            title = "Transform failed" if isinstance(e, TransformError) else "Transform error"
            msg = str(e) if isinstance(e, TransformError) else f"Unexpected error: {e}"
            QMessageBox.warning(self, title, msg)
            return None, None, None
        return snapshots, new_lengths, applied

    def _undo_snapshots(self, snapshots, new_lengths):
        """Undo applied snapshots (reverse order)."""
        for (lo, original), new_len in zip(
            reversed(snapshots), reversed(new_lengths)
        ):
            self._buffer.replace_range(lo, lo + new_len - 1, original)

    def _on_undo_transform(self):
        entry = self._xform_log.pop_last()
        if entry is None:
            return
        self._undo_snapshots(entry.snapshots, entry.new_lengths)
        self._mark_modified()
        self._broadcast_buffer_changed()

    def _on_redo_transform(self):
        entry = self._xform_log.pop_redo()
        if entry is None:
            return
        if not entry.steps:
            QMessageBox.warning(self, "Redo failed",
                                "Log entry has no recipe steps to replay.")
            return
        for step in entry.steps:
            if find_spec(step.spec_name) is None:
                QMessageBox.warning(self, "Redo failed",
                                    f"Unknown transform in recipe: {step.spec_name}")
                return
        try:
            for (lo, original), _new_len in zip(entry.snapshots, entry.new_lengths):
                hi = lo + len(original) - 1
                current = self._buffer.read(lo, len(original))
                new_bytes = apply_recipe(current, entry.steps)
                self._buffer.replace_range(lo, hi, new_bytes)
        except TransformError as e:
            QMessageBox.warning(self, "Redo failed", str(e))
            return
        self._xform_log.push_redo(entry)
        self._mark_modified()
        self._broadcast_buffer_changed()

    def _on_modify_transform(self, row: int):
        entries = self._xform_log.entries()
        if row < 0 or row >= len(entries):
            return
        entry = entries[row]

        if row != len(entries) - 1:
            QMessageBox.information(
                self, "Cannot modify",
                "Only the most recent transform can be edited directly.\n\n"
                "Undo the later transforms first, modify this one, then "
                "re-apply the others.")
            return

        if not entry.snapshots:
            return

        sorted_snaps = sorted(entry.snapshots, key=lambda s: s[0])
        probe = sorted_snaps[0][1][:4096]

        dlg = TransformDialog(
            has_selection=False, region_count=0, probe_bytes=probe,
            parent=self, initial_steps=list(entry.steps), edit_mode=True,
            probe_complete=len(sorted_snaps[0][1]) <= 4096)
        if dlg.exec() != dlg.DialogCode.Accepted:
            return
        new_req = dlg.get_request()
        if new_req is None or not new_req.steps:
            return

        # Undo original
        self._undo_snapshots(entry.snapshots, entry.new_lengths)

        ranges = sorted(
            (off, off + len(orig) - 1) for off, orig in entry.snapshots)

        if not recipe_length_preserving(new_req.steps) and len(ranges) > 1:
            prev_hi = -1
            for lo, hi in ranges:
                if lo <= prev_hi:
                    self._restore_entry_in_place(entry)
                    QMessageBox.warning(
                        self, "Overlapping ranges",
                        "This recipe changes length and cannot be applied to "
                        "overlapping regions.")
                    return
                prev_hi = hi

        snapshots, new_lengths, applied = self._apply_recipe_to_ranges(
            ranges, new_req.steps)
        if snapshots is None:
            self._restore_entry_in_place(entry)
            return

        new_entry = TransformLogEntry(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            op_name=_format_recipe_name(new_req.steps),
            scope_label=entry.scope_label,
            params_label=_format_recipe_params(new_req.steps),
            snapshots=snapshots,
            new_lengths=new_lengths,
            steps=list(new_req.steps),
        )
        self._xform_log.replace_entry(row, new_entry)
        self._mark_modified()
        self._broadcast_buffer_changed()

    def _restore_entry_in_place(self, entry: TransformLogEntry):
        try:
            for (lo, original), _new_len in zip(entry.snapshots, entry.new_lengths):
                hi = lo + len(original) - 1
                current = self._buffer.read(lo, len(original))
                new_bytes = apply_recipe(current, entry.steps)
                self._buffer.replace_range(lo, hi, new_bytes)
        except Exception:
            pass

    def _on_clear_transforms(self):
        if not self._xform_log.has_entries() and not self._xform_log.has_redo():
            return
        ret = QMessageBox.question(
            self, "Clear transform log",
            "Clearing the log will drop undo history but keep the current bytes.\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ret == QMessageBox.StandardButton.Yes:
            self._xform_log.clear_all()

    def _on_revert(self):
        if not self._xform_log.has_entries():
            QMessageBox.information(self, "Nothing to revert",
                                    "No transforms have been applied.")
            return
        ret = QMessageBox.question(
            self, "Revert all transforms",
            "Undo every applied transform and restore the original bytes?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ret != QMessageBox.StandardButton.Yes:
            return
        while self._xform_log.has_entries():
            self._on_undo_transform()
        self._xform_log.clear_all()
        self._mark_modified()
        self._broadcast_buffer_changed()

    def _on_save_as(self):
        if self._buffer is None or not self._buffer.filepath:
            QMessageBox.information(self, "Nothing to save", "Open a file first.")
            return False
        fp = self._buffer.filepath
        suggested = ''
        if fp and not fp.startswith('<'):
            p = Path(fp)
            suggested = str(p.with_name(f"{p.stem}.transformed{p.suffix}"))
        path, _ = QFileDialog.getSaveFileName(self, "Save As", suggested, "All Files (*)")
        if not path:
            return False
        if not self._buffer.save_to(path):
            QMessageBox.critical(self, "Save failed", f"Could not write to {path}")
            return False
        self._buffer.mark_saved(path)
        self._discard_recovery()
        self._mark_modified()
        self.statusBar().showMessage(f'Saved {self._buffer.size():,} bytes to {path}', 5000)
        return True

    def _on_save_selection_as(self):
        if self._buffer is None or self._buffer.size() == 0:
            QMessageBox.information(self, "Nothing to save", "Open a file first.")
            return

        ranges: list[tuple[int, int]] = []
        scope_label = ""
        if self._hex_widget.has_selection():
            lo, hi = self._hex_widget._ordered_selection()
            ranges = [(lo, hi)]
            scope_label = "selection"
        else:
            regions = self._hex_widget.pattern_regions()
            if regions:
                ranges = sorted(regions)
                scope_label = "regions"

        if not ranges:
            QMessageBox.information(
                self, "Nothing selected",
                "Select bytes in the hex view, or mark one or more regions, "
                "then try again.")
            return

        chunks = [self._buffer.read(lo, hi - lo + 1) for lo, hi in ranges]
        payload = b"".join(chunks)
        if not payload:
            QMessageBox.warning(self, "Empty selection",
                                "The selection contains zero bytes.")
            return

        suggested = ""
        fp = self._buffer.filepath
        if fp and fp != "<memory>":
            p = Path(fp)
            if scope_label == "selection":
                lo, hi = ranges[0]
                tag = f"sel_{lo:X}-{hi:X}"
            else:
                tag = f"regions_{len(ranges)}"
            suggested = str(p.with_name(f"{p.stem}.{tag}{p.suffix}"))

        path, _ = QFileDialog.getSaveFileName(
            self, "Save Selection As", suggested, "All Files (*)")
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(payload)
        except OSError as e:
            QMessageBox.critical(self, "Save failed",
                                 f"Could not write to {path}\n\n{e}")
            return

        detail = (f"{len(ranges):,} regions, {len(payload):,} bytes"
                  if scope_label == "regions"
                  else f"{len(payload):,} bytes")
        QMessageBox.information(self, "Saved",
                                f"Wrote {detail} to:\n{path}")

    def _mark_modified(self):
        title = self.windowTitle()
        if self._buffer and self._has_unsaved():
            if not title.endswith("*"):
                self.setWindowTitle(title + " *")
        else:
            if title.endswith(" *"):
                self.setWindowTitle(title[:-2])

    # ── Public API ─────────────────────────────────────────────────

    def set_file_list(self, file_paths: list[str], current_path: str = "",
                      hits_data: list | None = None):
        """Set a list of files for prev/next navigation.

        *current_path* determines the initial index.  *hits_data* is
        the full ``scan_hits`` list so match data can be loaded when
        navigating between files.  Call this **after** ``open_file``.
        """
        self._file_list = list(file_paths)
        self._hits_data = hits_data or []
        self._file_index = -1
        if current_path:
            resolved = str(Path(current_path).resolve())
            for i, fp in enumerate(self._file_list):
                try:
                    if str(Path(fp).resolve()) == resolved:
                        self._file_index = i
                        break
                except Exception:
                    continue
        self._update_nav_ui()

    def open_file(self, filepath: str, offset: int = 0, length: int = 0):
        buffer = HexDataBuffer()
        if not buffer.open_file(filepath):
            return False
        if not self._confirm_replace():
            buffer.close()
            return False
        self._buffer = buffer
        buffer.enable_recovery()
        self.setWindowTitle(f"Hex Editor — {Path(filepath).name}")
        self._distribute_buffer()
        self._status_format.setText(buffer.format_name)
        if offset > 0 or length > 0:
            self._hex_widget.navigate_to_offset(offset, length)
        return True

    def open_bytes(self, data: bytes, name: str = "<memory>", offset: int = 0):
        if not self._confirm_replace():
            return False
        self._buffer = HexDataBuffer()
        self._buffer.open_bytes(data, name)
        self._buffer.enable_recovery()
        self.setWindowTitle(f"Hex Editor — {name}")
        self._distribute_buffer()
        self._status_format.setText(self._buffer.format_name)
        if offset > 0:
            self._hex_widget.navigate_to_offset(offset)
        return True

    # ── YARA match data ──────────────────────────────────────────

    def set_match_data(self, matched_rules: list, file_data: bytes = b""):
        """Populate the YARA Matches dock with per-pattern hit rows.

        *matched_rules* is the list from a scan hit dict.  Each entry
        has ``identifier``, ``patterns`` → ``matches`` with offset/length.
        *file_data* is the raw file bytes for generating data previews.
        """
        self._match_table.setRowCount(0)
        if not matched_rules:
            self._match_dock.hide()
            return

        rows: list[tuple[str, str, int, int, str, str]] = []
        for rule in matched_rules:
            rule_name = rule.get("identifier", "?")
            for pat in rule.get("patterns", []):
                pat_id = pat.get("identifier", "?")
                for m in pat.get("matches", []):
                    offset = m.get("offset", 0)
                    length = m.get("length", 0)
                    hex_part = ""
                    ascii_part = ""
                    if file_data and offset < len(file_data):
                        chunk = file_data[offset:offset + min(length, 32)]
                        hex_part = " ".join(f"{b:02X}" for b in chunk)
                        ascii_part = "".join(
                            chr(b) if 0x20 <= b < 0x7F else "."
                            for b in chunk)
                    rows.append((rule_name, pat_id, offset, length,
                                 hex_part, ascii_part))

        rows.sort(key=lambda r: r[2])

        self._match_table.setRowCount(len(rows))
        for i, (rule, pat, off, ln, hexd, ascii_p) in enumerate(rows):
            self._match_table.setItem(i, 0, QTableWidgetItem(rule))
            self._match_table.setItem(i, 1, QTableWidgetItem(pat))

            off_item = QTableWidgetItem(f"0x{off:08X}")
            off_item.setData(Qt.ItemDataRole.UserRole, off)
            self._match_table.setItem(i, 2, off_item)

            ln_item = QTableWidgetItem(str(ln))
            ln_item.setData(Qt.ItemDataRole.UserRole, ln)
            self._match_table.setItem(i, 3, ln_item)

            self._match_table.setItem(i, 4, QTableWidgetItem(hexd))
            self._match_table.setItem(i, 5, QTableWidgetItem(ascii_p))

        self._match_dock.setWindowTitle(f"YARA Matches ({len(rows)})")
        self._match_dock.show()

    def _on_match_row_clicked(self, row: int, _col: int):
        """Navigate the hex view to the clicked match offset."""
        off_item = self._match_table.item(row, 2)
        ln_item = self._match_table.item(row, 3)
        if not off_item:
            return
        offset = off_item.data(Qt.ItemDataRole.UserRole)
        length = ln_item.data(Qt.ItemDataRole.UserRole) if ln_item else 0
        if offset is not None:
            self._hex_widget.navigate_to_offset(offset, length or 0)

    # ── File-list navigation ─────────────────────────────────────

    def _nav_prev(self):
        if not self._file_list or self._file_index <= 0:
            return
        previous = self._file_index
        self._file_index -= 1
        if not self._open_nav_file():
            self._file_index = previous
            self._update_nav_ui()

    def _nav_next(self):
        if not self._file_list or self._file_index >= len(self._file_list) - 1:
            return
        previous = self._file_index
        self._file_index += 1
        if not self._open_nav_file():
            self._file_index = previous
            self._update_nav_ui()

    def _open_nav_file(self):
        fp = self._file_list[self._file_index]
        if not Path(fp).exists() or not self.open_file(fp):
            return False
        if Path(fp).exists():
            # Load match data for this file if available
            self._load_match_data_for_path(fp)
        self._update_nav_ui()
        return True

    def _load_match_data_for_path(self, filepath: str):
        """Find and display match data for *filepath* from cached hits."""
        if not self._hits_data:
            return
        try:
            resolved = str(Path(filepath).resolve())
        except Exception:
            return
        for hit in self._hits_data:
            hit_fp = hit.get("filepath", "")
            try:
                if str(Path(hit_fp).resolve()) == resolved:
                    self.set_match_data(
                        hit.get("matched_rules", []),
                        hit.get("file_data", b""))
                    return
            except Exception:
                continue
        # No match data for this file
        self.set_match_data([])

    def _update_nav_ui(self):
        has_list = len(self._file_list) > 1
        self._navigation_toolbar.setVisible(has_list)
        self._prev_action.setEnabled(has_list and self._file_index > 0)
        self._next_action.setEnabled(
            has_list and self._file_index < len(self._file_list) - 1)
        if has_list and self._file_index >= 0:
            self._nav_label.setText(
                f" {self._file_index + 1}/{len(self._file_list)} ")
        else:
            self._nav_label.setText("")

    # ── Theming ────────────────────────────────────────────────────

    def apply_theme(self):
        if not self._theme_manager or not self._theme_manager.current_theme:
            return
        theme = self._theme_manager.current_theme
        qss = self._theme_manager.generate_qss_stylesheet(theme)
        self.setStyleSheet(qss)
        self._hex_widget.set_theme(theme.colors)

        font_name = theme.editor_font_family or "Cascadia Mono"
        font = QFont(font_name, theme.editor_font_size)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._hex_widget.setFont(font)
