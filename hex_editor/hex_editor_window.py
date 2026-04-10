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

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QFont, QKeySequence, QIcon
from PySide6.QtWidgets import (QMainWindow, QFileDialog, QDockWidget,
                               QStatusBar, QToolBar, QToolButton, QMenu,
                               QApplication, QLabel,
                               QMessageBox, QSpinBox, QWidget)

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

        icon_path = Path(__file__).parent.parent / "assets" / "YaraXGUI.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        self._theme_manager = theme_manager
        self._buffer = HexDataBuffer()
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

        # ── Signal wiring (Mediator pattern) ────────────────────────
        self._connect_signals()

        # ── Menus & toolbar ─────────────────────────────────────────
        self._setup_menus()
        self._setup_toolbar()
        self._setup_statusbar()

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
        for widget in self._buffer_aware:
            widget.set_buffer(self._buffer)
        self._hex_widget.set_buffer(self._buffer)
        self._status_size.setText(f"Size: {self._buffer.size():,}")

    def _broadcast_buffer_changed(self):
        """Re-push after transforms (invalidates caches)."""
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

        open_action = QAction("&Open...", self)
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
        edit_menu = menubar.addMenu("&Edit")

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

        xform_action = QAction("Apply &Transform...", self)
        xform_action.triggered.connect(self._on_apply_transform)
        edit_menu.addAction(xform_action)

        edit_menu.addSeparator()

        goto_action = QAction("&Go to Offset...", self)
        goto_action.setShortcut(QKeySequence("Ctrl+G"))
        goto_action.triggered.connect(self._on_goto)
        edit_menu.addAction(goto_action)

        find_action = QAction("&Find...", self)
        find_action.setShortcut(QKeySequence.StandardKey.Find)
        find_action.triggered.connect(self._on_find)
        edit_menu.addAction(find_action)

        # ── View ───────────────────────────────────────────────────
        view_menu = menubar.addMenu("&View")

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

        view_menu.addSeparator()

        # Panels submenu — keeps the View menu clean
        panels_menu = view_menu.addMenu("&Panels")
        for dock in self._docks.values():
            panels_menu.addAction(dock.toggleViewAction())

    def _setup_toolbar(self):
        toolbar = QToolBar("Main", self)
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        # ── Primary actions (always visible) ───────────────────────
        for label, tip, handler in [
            ("Open", "Open file (Ctrl+O)", self._on_open),
            ("Goto", "Go to offset (Ctrl+G)", self._on_goto),
            ("Find", "Find pattern (Ctrl+F)", self._on_find),
        ]:
            act = QAction(label, self)
            act.setToolTip(tip)
            act.triggered.connect(handler)
            toolbar.addAction(act)

        toolbar.addSeparator()

        # ── Panels dropdown (replaces 8+ individual toggle buttons) ─
        panels_btn = QToolButton(self)
        panels_btn.setText("Panels")
        panels_btn.setToolTip("Show/hide analysis panels")
        panels_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        panels_menu = QMenu(self)
        for dock in self._docks.values():
            panels_menu.addAction(dock.toggleViewAction())
        panels_btn.setMenu(panels_menu)
        toolbar.addWidget(panels_btn)

        act_xform = QAction("Transform", self)
        act_xform.setToolTip("Apply a data transform (Edit > Apply Transform)")
        act_xform.triggered.connect(self._on_apply_transform)
        toolbar.addAction(act_xform)

        toolbar.addSeparator()

        # ── View mode toggles ──────────────────────────────────────
        self._view_toggle_btn = QAction("Text", self)
        self._view_toggle_btn.setToolTip("Switch to text view (Ctrl+T)")
        self._view_toggle_btn.setCheckable(True)
        self._view_toggle_btn.toggled.connect(self._toggle_view_action.setChecked)
        toolbar.addAction(self._view_toggle_btn)

        self._escape_text_action = QAction("Escape", self)
        self._escape_text_action.setCheckable(True)
        self._escape_text_action.setChecked(False)
        self._escape_text_action.setToolTip(
            "Off: notepad view with real newlines.\n"
            "On: fixed 64-byte grid, non-printable as \u00b7")
        self._escape_text_action.toggled.connect(self._on_toggle_text_escape_mode)
        toolbar.addAction(self._escape_text_action)

        toolbar.addSeparator()

        # ── Bytes per row ──────────────────────────────────────────
        toolbar.addWidget(QLabel(" Bytes/row: "))
        self._bpl_spin = QSpinBox(toolbar)
        self._bpl_spin.setRange(4, 64)
        self._bpl_spin.setSingleStep(1)
        self._bpl_spin.setValue(self._hex_widget.bytes_per_line())
        self._bpl_spin.setToolTip(
            "Bytes per row in hex view (4\u201364). Common: 8, 16, 24, 32.")
        self._bpl_spin.valueChanged.connect(self._hex_widget.set_bytes_per_line)
        self._hex_widget.bytes_per_line_changed.connect(self._on_bpl_changed)
        toolbar.addWidget(self._bpl_spin)

        toolbar.addSeparator()

        # ── Read-only lock toggle ──────────────────────────────────
        self._lock_action = QAction("\U0001F512 Read-Only", self)
        self._lock_action.setCheckable(True)
        self._lock_action.setChecked(True)  # locked by default
        self._lock_action.setToolTip(
            "Locked: editing disabled (safe browsing).\n"
            "Click to unlock and allow byte editing.")
        self._lock_action.toggled.connect(self._on_lock_toggled)
        toolbar.addAction(self._lock_action)

    def _on_lock_toggled(self, locked: bool):
        self._hex_widget.read_only = locked
        if locked:
            self._lock_action.setText("\U0001F512 Read-Only")
            self._lock_action.setToolTip(
                "Locked: editing disabled (safe browsing).\n"
                "Click to unlock and allow byte editing.")
        else:
            self._lock_action.setText("\U0001F513 Editable")
            self._lock_action.setToolTip(
                "Unlocked: byte editing enabled.\n"
                "Click to lock and prevent accidental edits.")

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
        self._status_mode = QLabel("\U0001F512 Read-Only")
        self._status_mode.setToolTip("Click the lock button in the toolbar to toggle editing")
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
        if read_only:
            self._status_mode.setText("\U0001F512 Read-Only")
        else:
            self._status_mode.setText("\U0001F513 Editable")

    # ── Actions ────────────────────────────────────────────────────

    def _on_open(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "All Files (*)")
        if filepath:
            self.open_file(filepath)

    def _on_toggle_view_mode(self, text_mode: bool):
        self._hex_widget.set_text_mode(text_mode)
        self._view_toggle_btn.setChecked(text_mode)
        label = "Hex" if text_mode else "Text"
        tooltip = f"Switch to {'hex' if text_mode else 'text'} view (Ctrl+T)"
        self._view_toggle_btn.setText(label)
        self._view_toggle_btn.setToolTip(tooltip)
        self._toggle_view_action.setText("&Hex View" if text_mode else "&Text View")

    def _on_toggle_text_escape_mode(self, escape: bool):
        self._hex_widget.set_text_escape_mode(escape)
        for act in (self._escape_text_action, self._toggle_escape_action):
            if act.isChecked() != escape:
                act.blockSignals(True)
                try:
                    act.setChecked(escape)
                finally:
                    act.blockSignals(False)

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

    def _on_disassemble_requested(self, code: bytes, base_offset: int):
        self._docks["disasm_widget"].show()
        self._docks["disasm_widget"].raise_()
        self._disasm_widget.disassemble_bytes(code, base_offset)

    def _on_data_edited(self):
        """Handle direct byte edits from the hex widget (typing, delete, etc.)."""
        self._mark_modified()
        self._inspector.set_buffer(self._buffer)
        self._status_size.setText(f"Size: {self._buffer.size():,}")

        # Refresh the edit log table
        editor = self._hex_widget._editor
        history = editor.edit_history
        self._edit_log.refresh(history)
        if history:
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
        if regions:
            lo, hi = regions[0]
            probe = self._buffer.read(lo, min(PROBE_MAX, hi - lo + 1))
        elif has_sel:
            sel_lo, sel_hi = self._hex_widget._ordered_selection()
            probe = self._buffer.read(sel_lo, min(PROBE_MAX, sel_hi - sel_lo + 1))
        else:
            probe = self._buffer.read(0, PROBE_MAX)

        dlg = TransformDialog(has_sel, len(regions), probe_bytes=probe, parent=self)
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
            parent=self, initial_steps=list(entry.steps), edit_mode=True)
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
        if self._buffer is None or self._buffer.size() == 0:
            QMessageBox.information(self, "Nothing to save", "Open a file first.")
            return
        suggested = ""
        fp = self._buffer.filepath
        if fp and fp != "<memory>":
            p = Path(fp)
            suggested = str(p.with_name(f"{p.stem}.transformed{p.suffix}"))
        path, _ = QFileDialog.getSaveFileName(
            self, "Save As", suggested, "All Files (*)")
        if not path:
            return
        if self._buffer.save_to(path):
            QMessageBox.information(
                self, "Saved",
                f"Wrote {self._buffer.size():,} bytes to:\n{path}")
        else:
            QMessageBox.critical(self, "Save failed",
                                 f"Could not write to {path}")

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
        if self._buffer and self._buffer.is_modified():
            if not title.endswith("*"):
                self.setWindowTitle(title + " *")
        else:
            if title.endswith(" *"):
                self.setWindowTitle(title[:-2])

    # ── Public API ─────────────────────────────────────────────────

    def open_file(self, filepath: str, offset: int = 0, length: int = 0):
        if not self._buffer.open_file(filepath):
            return
        self.setWindowTitle(f"Hex Editor \u2014 {Path(filepath).name}")
        self._distribute_buffer()
        self._status_format.setText(self._buffer.format_name)
        if offset > 0 or length > 0:
            self._hex_widget.navigate_to_offset(offset, length)

    def open_bytes(self, data: bytes, name: str = "<memory>", offset: int = 0):
        if not self._buffer.open_bytes(data, name):
            return
        self.setWindowTitle(f"Hex Editor \u2014 {name}")
        self._distribute_buffer()
        self._status_format.setText(self._buffer.format_name)
        if offset > 0:
            self._hex_widget.navigate_to_offset(offset)

    # ── Theming ────────────────────────────────────────────────────

    def apply_theme(self):
        if not self._theme_manager or not self._theme_manager.current_theme:
            return
        theme = self._theme_manager.current_theme
        qss = self._theme_manager.generate_qss_stylesheet(theme)
        self.setStyleSheet(qss)
        self._hex_widget.set_theme(theme.colors)

        font_name = theme.font_family or "Cascadia Code"
        font = QFont(font_name, 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._hex_widget.setFont(font)
