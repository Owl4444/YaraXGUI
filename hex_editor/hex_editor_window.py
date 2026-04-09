# -*- coding: utf-8 -*-
"""Main hex editor window — standalone QMainWindow."""

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QFont, QKeySequence, QIcon
from PySide6.QtWidgets import (QMainWindow, QFileDialog, QDockWidget,
                               QStatusBar, QToolBar, QApplication, QLabel,
                               QMessageBox)

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


def _format_scope(scope: str, ranges: list[tuple[int, int]]) -> str:
    """Human-readable scope label for the log table."""
    if scope == "entire":
        return "Entire file"
    if scope == "selection":
        if not ranges:
            return "Selection"
        lo, hi = ranges[0]
        return f"Selection 0x{lo:X}-0x{hi:X}"
    # regions
    if not ranges:
        return "Regions"
    if len(ranges) <= 3:
        parts = [f"0x{lo:X}-0x{hi:X}" for lo, hi in ranges]
        return "Regions: " + ", ".join(parts)
    lo0, hi0 = ranges[0]
    return f"Regions: 0x{lo0:X}-0x{hi0:X} … (+{len(ranges) - 1} more)"


def _format_params(params: dict) -> str:
    """Compact params label for a single step (truncates long hex)."""
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
    """Render a recipe as ``step1 \u2192 step2 \u2192 step3``."""
    if not steps:
        return "(empty)"
    return " \u2192 ".join(step.spec_name for step in steps)


def _format_recipe_params(steps: list[RecipeStep]) -> str:
    """Render per-step params as ``step1: k=v | step2: k=v``."""
    parts = []
    for step in steps:
        if not step.params:
            continue
        parts.append(f"{step.spec_name}: {_format_params(step.params)}")
    return " | ".join(parts)


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

        # Entropy (bottom)
        self._entropy_widget = EntropyWidget(self)
        self._entropy_dock = QDockWidget("Entropy", self)
        self._entropy_dock.setWidget(self._entropy_widget)
        self._entropy_dock.setAllowedAreas(Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.TopDockWidgetArea)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._entropy_dock)
        self._entropy_dock.hide()

        # XOR Scanner (bottom)
        self._xor_widget = XorScannerWidget(self)
        self._xor_dock = QDockWidget("XOR Scanner", self)
        self._xor_dock.setWidget(self._xor_widget)
        self._xor_dock.setAllowedAreas(Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.TopDockWidgetArea)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._xor_dock)
        self._xor_dock.hide()

        # Disassembly (bottom)
        self._disasm_widget = DisasmWidget(self)
        self._disasm_dock = QDockWidget("Disassembly", self)
        self._disasm_dock.setWidget(self._disasm_widget)
        self._disasm_dock.setAllowedAreas(Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.TopDockWidgetArea)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._disasm_dock)
        self._disasm_dock.hide()

        # Transforms log (bottom, hidden until first transform)
        self._xform_log = TransformLogWidget(self)
        self._xform_dock = QDockWidget("Transforms", self)
        self._xform_dock.setWidget(self._xform_log)
        self._xform_dock.setAllowedAreas(Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.TopDockWidgetArea)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._xform_dock)
        self._xform_dock.hide()

        # ── Connections ─────────────────────────────────────────────

        self._hex_widget.cursor_moved.connect(self._on_cursor_moved)
        self._format_viewer.navigate_requested.connect(self._hex_widget.navigate_to_offset)
        self._strings_widget.navigate_requested.connect(self._hex_widget.navigate_to_offset)
        self._entropy_widget.navigate_requested.connect(self._hex_widget.navigate_to_offset)
        self._xor_widget.navigate_requested.connect(self._hex_widget.navigate_to_offset)
        self._hex_widget.yara_pattern_requested.connect(self.yara_pattern_generated.emit)
        self._hex_widget.pattern_regions_changed.connect(self._on_pattern_regions_changed)
        self._hex_widget.cursor_moved.connect(self._entropy_widget.set_cursor_offset)
        self._disasm_widget.navigate_requested.connect(self._hex_widget.navigate_to_offset)
        self._hex_widget.disassemble_requested.connect(self._on_disassemble_requested)
        self._hex_widget.transform_requested.connect(self._on_apply_transform)
        self._xform_log.undo_requested.connect(self._on_undo_transform)
        self._xform_log.redo_requested.connect(self._on_redo_transform)
        self._xform_log.clear_requested.connect(self._on_clear_transforms)
        self._xform_log.navigate_requested.connect(self._hex_widget.navigate_to_offset)
        self._xform_log.modify_requested.connect(self._on_modify_transform)

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

        save_as_action = QAction("Save &As...", self)
        save_as_action.setShortcut(QKeySequence("Ctrl+Shift+S"))
        save_as_action.triggered.connect(self._on_save_as)
        file_menu.addAction(save_as_action)

        save_sel_action = QAction("Save Se&lection As...", self)
        save_sel_action.setShortcut(QKeySequence("Ctrl+Shift+E"))
        save_sel_action.setToolTip(
            "Save the current selection (or marked regions, concatenated) to a new file"
        )
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

        self._toggle_view_action = QAction("&Text View", self)
        self._toggle_view_action.setShortcut(QKeySequence("Ctrl+T"))
        self._toggle_view_action.setCheckable(True)
        self._toggle_view_action.setChecked(False)
        self._toggle_view_action.toggled.connect(self._on_toggle_view_mode)
        view_menu.addAction(self._toggle_view_action)
        view_menu.addSeparator()

        view_menu.addAction(self._format_dock.toggleViewAction())
        view_menu.addAction(self._inspector_dock.toggleViewAction())
        view_menu.addAction(self._strings_dock.toggleViewAction())
        view_menu.addAction(self._entropy_dock.toggleViewAction())
        view_menu.addAction(self._xor_dock.toggleViewAction())
        view_menu.addAction(self._disasm_dock.toggleViewAction())
        view_menu.addAction(self._xform_dock.toggleViewAction())

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

        entropy_action = QAction("Entropy", self)
        entropy_action.setToolTip("Toggle entropy heatmap")
        entropy_action.triggered.connect(lambda: self._entropy_dock.setVisible(not self._entropy_dock.isVisible()))
        toolbar.addAction(entropy_action)

        xor_action = QAction("XOR Scan", self)
        xor_action.setToolTip("Toggle XOR string scanner")
        xor_action.triggered.connect(lambda: self._xor_dock.setVisible(not self._xor_dock.isVisible()))
        toolbar.addAction(xor_action)

        disasm_action = QAction("Disasm", self)
        disasm_action.setToolTip("Toggle disassembly panel")
        disasm_action.triggered.connect(lambda: self._disasm_dock.setVisible(not self._disasm_dock.isVisible()))
        toolbar.addAction(disasm_action)

        xform_action = QAction("Transform", self)
        xform_action.setToolTip("Apply a data transform to the selection/regions")
        xform_action.triggered.connect(self._on_apply_transform)
        toolbar.addAction(xform_action)

        xform_log_action = QAction("Xform Log", self)
        xform_log_action.setToolTip("Toggle transforms log panel")
        xform_log_action.triggered.connect(lambda: self._xform_dock.setVisible(not self._xform_dock.isVisible()))
        toolbar.addAction(xform_log_action)

        toolbar.addSeparator()

        self._view_toggle_btn = QAction("Text", self)
        self._view_toggle_btn.setToolTip("Switch to text view (Ctrl+T)")
        self._view_toggle_btn.setCheckable(True)
        self._view_toggle_btn.toggled.connect(self._toggle_view_action.setChecked)
        toolbar.addAction(self._view_toggle_btn)

    def _setup_statusbar(self):
        self._status_offset = QLabel("Offset: 0x00000000")
        self._status_size = QLabel("Size: 0")
        self._status_regions = QLabel("")
        self._status_format = QLabel("")
        sb = self.statusBar()
        sb.addWidget(self._status_offset)
        sb.addWidget(self._status_size)
        sb.addWidget(self._status_regions)
        sb.addPermanentWidget(self._status_format)

    # ── Actions ─────────────────────────────────────────────────────

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

    def _on_pattern_regions_changed(self, count: int):
        if count > 0:
            self._status_regions.setText(f"Pattern regions: {count}")
        else:
            self._status_regions.setText("")

    def _on_disassemble_requested(self, code: bytes, base_offset: int):
        self._disasm_dock.show()
        self._disasm_dock.raise_()
        self._disasm_widget.disassemble_bytes(code, base_offset)

    # ── Transform handlers ──────────────────────────────────────────

    def _on_apply_transform(self):
        if self._buffer is None or self._buffer.size() == 0:
            QMessageBox.information(self, "No data", "Open a file first.")
            return

        has_sel = self._hex_widget.has_selection()
        regions = self._hex_widget.pattern_regions()

        # Probe: bytes from the most-specific current scope, for live preview.
        # The upper bound must be >= the maximum value the TransformDialog's
        # "Show" spinner allows (see PREVIEW_BYTES_MAX in transform_dialog.py)
        # so that users can grow the preview without re-opening the dialog.
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

        # Resolve scope → list of inclusive (lo, hi) ranges
        if req.scope == "selection":
            if not has_sel:
                return
            lo, hi = self._hex_widget._ordered_selection()
            ranges = [(lo, hi)]
        elif req.scope == "regions":
            ranges = sorted(regions)
        else:  # entire
            ranges = [(0, self._buffer.size() - 1)]

        if not ranges:
            return

        # Reject overlapping ranges for length-changing recipes
        if not recipe_length_preserving(req.steps) and len(ranges) > 1:
            prev_hi = -1
            for lo, hi in ranges:
                if lo <= prev_hi:
                    QMessageBox.warning(
                        self, "Overlapping ranges",
                        "This recipe changes length and cannot be applied to "
                        "overlapping regions. Please clear or merge regions first.",
                    )
                    return
                prev_hi = hi

        # Apply in reverse order so length changes don't shift earlier offsets.
        # Keep snapshots + new lengths aligned (both in reverse-application order).
        snapshots: list[tuple[int, bytes]] = []
        new_lengths: list[int] = []
        applied: list[tuple[int, int, int]] = []  # (lo, original_len, new_len) for rollback
        try:
            for lo, hi in sorted(ranges, reverse=True):
                original = self._buffer.read(lo, hi - lo + 1)
                new_bytes = apply_recipe(original, req.steps)
                snapshots.append((lo, original))
                new_lengths.append(len(new_bytes))
                self._buffer.replace_range(lo, hi, new_bytes)
                applied.append((lo, len(original), len(new_bytes)))
        except TransformError as e:
            # Roll back in REVERSE of apply order (low-offset first) so stored
            # offsets remain valid as the buffer shrinks back to its pre-apply
            # size.  Each step undoes one range of length ``new_len`` back to
            # the captured ``original`` bytes.
            for (lo, _orig_len, new_len), (_lo2, original) in zip(
                reversed(applied), reversed(snapshots)
            ):
                self._buffer.replace_range(lo, lo + new_len - 1, original)
            QMessageBox.warning(self, "Transform failed", str(e))
            return
        except Exception as e:  # defensive
            for (lo, _orig_len, new_len), (_lo2, original) in zip(
                reversed(applied), reversed(snapshots)
            ):
                self._buffer.replace_range(lo, lo + new_len - 1, original)
            QMessageBox.critical(self, "Transform error", f"Unexpected error: {e}")
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

    def _on_undo_transform(self):
        entry = self._xform_log.pop_last()
        if entry is None:
            return
        # Apply was done high-offset → low-offset. Undo must go low → high so
        # each stored offset still points at its (possibly shifted) new bytes
        # when we restore them.  snapshots/new_lengths are in apply order so
        # we simply iterate them in reverse here.
        for (lo, original), new_len in zip(
            reversed(entry.snapshots), reversed(entry.new_lengths)
        ):
            self._buffer.replace_range(lo, lo + new_len - 1, original)
        self._mark_modified()
        self._broadcast_buffer_changed()

    def _on_redo_transform(self):
        entry = self._xform_log.pop_redo()
        if entry is None:
            return
        if not entry.steps:
            QMessageBox.warning(
                self, "Redo failed",
                "Log entry has no recipe steps to replay.",
            )
            return
        # Validate all steps exist in the registry before touching anything.
        for step in entry.steps:
            if find_spec(step.spec_name) is None:
                QMessageBox.warning(
                    self, "Redo failed",
                    f"Unknown transform in recipe: {step.spec_name}",
                )
                return
        # snapshots are in reverse-application order (high → low offsets),
        # which is the same order we need to re-apply in so length-changing
        # ops don't shift earlier offsets.
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
        """Edit the recipe of an existing log entry in place.

        Only the most recent entry can be edited because later transforms
        depend on the result of earlier ones.  We undo the entry, run the
        new recipe on the same byte ranges, and replace the row in place.
        On any failure we re-apply the original recipe so the buffer state
        stays consistent.
        """
        entries = self._xform_log.entries()
        if row < 0 or row >= len(entries):
            return
        entry = entries[row]

        if row != len(entries) - 1:
            QMessageBox.information(
                self, "Cannot modify",
                "Only the most recent transform can be edited directly.\n\n"
                "Undo the later transforms first, modify this one, then "
                "re-apply the others.",
            )
            return

        if not entry.snapshots:
            return

        # Probe = the original input bytes (before the recipe ran), pulled
        # from the saved snapshot of the lowest-offset region. Cap at the
        # same upper bound as the live-apply path so the preview spinner
        # has the same range.
        sorted_snaps = sorted(entry.snapshots, key=lambda s: s[0])
        probe = sorted_snaps[0][1][:4096]

        dlg = TransformDialog(
            has_selection=False,
            region_count=0,
            probe_bytes=probe,
            parent=self,
            initial_steps=list(entry.steps),
            edit_mode=True,
        )
        if dlg.exec() != dlg.DialogCode.Accepted:
            return
        new_req = dlg.get_request()
        if new_req is None or not new_req.steps:
            return

        # Step 1: undo the original entry (restore originals into buffer).
        # snapshots/new_lengths are in reverse-application order, so undo
        # in REVERSE of that (low → high) so each stored offset is still
        # valid as the buffer shrinks back.
        for (lo, original), new_len in zip(
            reversed(entry.snapshots), reversed(entry.new_lengths)
        ):
            self._buffer.replace_range(lo, lo + new_len - 1, original)

        # Reconstruct the (lo, hi) ranges from the now-restored snapshots.
        ranges = sorted(
            (off, off + len(orig) - 1) for off, orig in entry.snapshots
        )

        # Reject overlapping ranges for length-changing recipes (same rule
        # as _on_apply_transform).
        if not recipe_length_preserving(new_req.steps) and len(ranges) > 1:
            prev_hi = -1
            for lo, hi in ranges:
                if lo <= prev_hi:
                    self._restore_entry_in_place(entry)
                    QMessageBox.warning(
                        self, "Overlapping ranges",
                        "This recipe changes length and cannot be applied to "
                        "overlapping regions.",
                    )
                    return
                prev_hi = hi

        # Step 2: apply the new recipe in reverse-offset order.
        new_snapshots: list[tuple[int, bytes]] = []
        new_new_lengths: list[int] = []
        applied: list[tuple[int, int, int]] = []
        try:
            for lo, hi in sorted(ranges, reverse=True):
                original = self._buffer.read(lo, hi - lo + 1)
                new_bytes = apply_recipe(original, new_req.steps)
                new_snapshots.append((lo, original))
                new_new_lengths.append(len(new_bytes))
                self._buffer.replace_range(lo, hi, new_bytes)
                applied.append((lo, len(original), len(new_bytes)))
        except TransformError as e:
            # Rollback the new recipe, then re-apply the original.
            for (lo, _ol, nl), (_lo2, orig) in zip(
                reversed(applied), reversed(new_snapshots)
            ):
                self._buffer.replace_range(lo, lo + nl - 1, orig)
            self._restore_entry_in_place(entry)
            QMessageBox.warning(self, "Modification failed", str(e))
            return
        except Exception as e:  # defensive
            for (lo, _ol, nl), (_lo2, orig) in zip(
                reversed(applied), reversed(new_snapshots)
            ):
                self._buffer.replace_range(lo, lo + nl - 1, orig)
            self._restore_entry_in_place(entry)
            QMessageBox.critical(self, "Modification error",
                                 f"Unexpected error: {e}")
            return

        # Step 3: build a new log entry and swap it in place.
        new_entry = TransformLogEntry(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            op_name=_format_recipe_name(new_req.steps),
            scope_label=entry.scope_label,
            params_label=_format_recipe_params(new_req.steps),
            snapshots=new_snapshots,
            new_lengths=new_new_lengths,
            steps=list(new_req.steps),
        )
        self._xform_log.replace_entry(row, new_entry)
        self._mark_modified()
        self._broadcast_buffer_changed()

    def _restore_entry_in_place(self, entry: TransformLogEntry):
        """Re-apply ``entry``'s recipe to its original bytes (used on rollback).

        Used when a modify-in-place attempt fails after we've already undone
        the original entry — this puts the buffer back exactly the way the
        log row claims it is.
        """
        try:
            for (lo, original), _new_len in zip(entry.snapshots, entry.new_lengths):
                hi = lo + len(original) - 1
                current = self._buffer.read(lo, len(original))
                new_bytes = apply_recipe(current, entry.steps)
                self._buffer.replace_range(lo, hi, new_bytes)
        except Exception:
            # Worst case: just leave the originals in the buffer.  The log
            # row will be slightly out of sync but the user can undo it.
            pass

    def _on_clear_transforms(self):
        if not self._xform_log.has_entries() and not self._xform_log.has_redo():
            return
        ret = QMessageBox.question(
            self, "Clear transform log",
            "Clearing the log will drop undo history but keep the current bytes.\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
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
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
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
        path, _ = QFileDialog.getSaveFileName(self, "Save As", suggested, "All Files (*)")
        if not path:
            return
        if self._buffer.save_to(path):
            QMessageBox.information(
                self, "Saved",
                f"Wrote {self._buffer.size():,} bytes to:\n{path}",
            )
        else:
            QMessageBox.critical(self, "Save failed",
                                 f"Could not write to {path}")

    def _on_save_selection_as(self):
        """Save the current selection (or marked regions concatenated) to a file."""
        if self._buffer is None or self._buffer.size() == 0:
            QMessageBox.information(self, "Nothing to save", "Open a file first.")
            return

        # Resolve scope: prefer explicit selection, fall back to marked regions.
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
                "then try again.",
            )
            return

        # Concatenate every range in offset order.
        chunks: list[bytes] = []
        for lo, hi in ranges:
            chunks.append(self._buffer.read(lo, hi - lo + 1))
        payload = b"".join(chunks)
        if not payload:
            QMessageBox.warning(self, "Empty selection",
                                "The selection contains zero bytes.")
            return

        # Suggest a default filename based on the source path + scope.
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

        if scope_label == "regions":
            detail = f"{len(ranges):,} regions, {len(payload):,} bytes"
        else:
            detail = f"{len(payload):,} bytes"
        QMessageBox.information(
            self, "Saved",
            f"Wrote {detail} to:\n{path}",
        )

    def _broadcast_buffer_changed(self):
        """Re-push the buffer to every dock so their caches are invalidated."""
        self._inspector.set_buffer(self._buffer)
        self._format_viewer.set_buffer(self._buffer)
        self._strings_widget.set_buffer(self._buffer)
        self._entropy_widget.set_buffer(self._buffer)
        self._xor_widget.set_buffer(self._buffer)
        self._disasm_widget.set_buffer(self._buffer)
        self._hex_widget.refresh_after_data_change()
        self._status_size.setText(f"Size: {self._buffer.size():,}")

    def _mark_modified(self):
        """Add a ``*`` suffix to the window title once the buffer is dirty."""
        title = self.windowTitle()
        if self._buffer and self._buffer.is_modified():
            if not title.endswith("*"):
                self.setWindowTitle(title + " *")
        else:
            if title.endswith(" *"):
                self.setWindowTitle(title[:-2])

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
        self._entropy_widget.set_buffer(self._buffer)
        self._xor_widget.set_buffer(self._buffer)
        self._disasm_widget.set_buffer(self._buffer)

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
        self._entropy_widget.set_buffer(self._buffer)
        self._xor_widget.set_buffer(self._buffer)
        self._disasm_widget.set_buffer(self._buffer)

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
