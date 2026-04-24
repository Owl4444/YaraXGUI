# -*- coding: utf-8 -*-
"""Standalone window for binary-diffing two files side by side.

Two HexWidgets in a horizontal splitter with synchronized scrolling.
Diff bytes are highlighted with a yellow tint in both views.  F7 /
Shift+F7 jump between diff regions.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QKeySequence, QIcon
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QLabel, QPushButton,
                               QFileDialog, QSplitter, QToolBar,
                               QMessageBox, QStatusBar)

from .hex_data_buffer import HexDataBuffer
from .hex_widget import HexWidget
from .binary_diff import BinaryDiffModel


class BinaryDiffWindow(QMainWindow):
    """Compare two files side by side with byte-level diff highlighting."""

    def __init__(self, theme_manager=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Binary Diff")
        self.resize(1500, 800)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)

        icon_path = Path(__file__).parent.parent / "assets" / "YaraXGUI.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        self._theme_manager = theme_manager
        self._buf_left = HexDataBuffer()
        self._buf_right = HexDataBuffer()
        self._diff: BinaryDiffModel | None = None
        self._syncing_scroll = False  # re-entrancy guard

        # ── Central layout: two HexWidgets in a splitter ───────────
        central = QWidget(self)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(2)

        # Path labels above each pane
        path_row = QHBoxLayout()
        self._path_left_label = QLabel("(left: no file loaded)")
        self._path_left_label.setStyleSheet(
            "color: gray; font-style: italic; padding: 2px;")
        self._path_right_label = QLabel("(right: no file loaded)")
        self._path_right_label.setStyleSheet(
            "color: gray; font-style: italic; padding: 2px;")
        path_row.addWidget(self._path_left_label, 1)
        path_row.addWidget(self._path_right_label, 1)
        layout.addLayout(path_row)

        # Splitter with the two views
        splitter = QSplitter(Qt.Orientation.Horizontal, central)

        self._hex_left = HexWidget(self)
        self._hex_right = HexWidget(self)

        splitter.addWidget(self._hex_left)
        splitter.addWidget(self._hex_right)
        splitter.setSizes([700, 700])
        splitter.setChildrenCollapsible(False)
        layout.addWidget(splitter, 1)

        self.setCentralWidget(central)

        # ── Synchronised scrolling ─────────────────────────────────
        self._hex_left.verticalScrollBar().valueChanged.connect(
            lambda v: self._sync_scroll(self._hex_right, v))
        self._hex_right.verticalScrollBar().valueChanged.connect(
            lambda v: self._sync_scroll(self._hex_left, v))

        # ── Mirror cursor between panes ────────────────────────────
        self._hex_left.cursor_moved.connect(
            lambda off: self._mirror_cursor(self._hex_right, off))
        self._hex_right.cursor_moved.connect(
            lambda off: self._mirror_cursor(self._hex_left, off))
        self._hex_left.cursor_moved.connect(self._on_cursor_moved)

        # ── Toolbar ────────────────────────────────────────────────
        self._setup_toolbar()

        # ── Status bar ─────────────────────────────────────────────
        self._status_summary = QLabel("Open two files to begin")
        self._status_pos = QLabel("")
        sb = QStatusBar(self)
        sb.addWidget(self._status_summary)
        sb.addPermanentWidget(self._status_pos)
        self.setStatusBar(sb)

        # Apply theme if supplied
        if self._theme_manager and self._theme_manager.current_theme:
            self._hex_left.set_theme(self._theme_manager.current_theme.colors)
            self._hex_right.set_theme(self._theme_manager.current_theme.colors)
            qss = self._theme_manager.generate_qss_stylesheet(
                self._theme_manager.current_theme)
            self.setStyleSheet(qss)

    # ── Toolbar ────────────────────────────────────────────────────

    def _setup_toolbar(self):
        toolbar = QToolBar("Diff", self)
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        act_open_left = QAction("Open Left\u2026", self)
        act_open_left.setToolTip("Load the left-side file")
        act_open_left.triggered.connect(self._on_open_left)
        toolbar.addAction(act_open_left)

        act_open_right = QAction("Open Right\u2026", self)
        act_open_right.setToolTip("Load the right-side file")
        act_open_right.triggered.connect(self._on_open_right)
        toolbar.addAction(act_open_right)

        toolbar.addSeparator()

        act_swap = QAction("Swap", self)
        act_swap.setToolTip("Swap left and right files")
        act_swap.triggered.connect(self._on_swap)
        toolbar.addAction(act_swap)

        act_refresh = QAction("Recompute Diff", self)
        act_refresh.setToolTip("Recompute the diff after edits")
        act_refresh.triggered.connect(self._recompute_diff)
        toolbar.addAction(act_refresh)

        toolbar.addSeparator()

        act_prev = QAction("\u25C0 Prev Diff", self)
        act_prev.setShortcut(QKeySequence("Shift+F7"))
        act_prev.setToolTip("Jump to previous diff region (Shift+F7)")
        act_prev.triggered.connect(self._on_prev_diff)
        toolbar.addAction(act_prev)

        act_next = QAction("Next Diff \u25B6", self)
        act_next.setShortcut(QKeySequence("F7"))
        act_next.setToolTip("Jump to next diff region (F7)")
        act_next.triggered.connect(self._on_next_diff)
        toolbar.addAction(act_next)

    # ── Public API ─────────────────────────────────────────────────

    def open_left_file(self, filepath: str):
        if self._buf_left.open_file(filepath):
            self._hex_left.set_buffer(self._buf_left)
            self._path_left_label.setText(self._format_path(filepath, "left"))
            self._path_left_label.setToolTip(filepath)
            self._path_left_label.setStyleSheet("padding: 2px;")
            self._maybe_compute_diff()

    def open_right_file(self, filepath: str):
        if self._buf_right.open_file(filepath):
            self._hex_right.set_buffer(self._buf_right)
            self._path_right_label.setText(self._format_path(filepath, "right"))
            self._path_right_label.setToolTip(filepath)
            self._path_right_label.setStyleSheet("padding: 2px;")
            self._maybe_compute_diff()

    @staticmethod
    def _format_path(filepath: str, side: str) -> str:
        name = Path(filepath).name
        size = Path(filepath).stat().st_size if Path(filepath).exists() else 0
        return f"\u25CF {side}: {name} ({size:,} bytes)"

    # ── Slots ──────────────────────────────────────────────────────

    def _on_open_left(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Left File", "", "All Files (*)")
        if path:
            self.open_left_file(path)

    def _on_open_right(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Right File", "", "All Files (*)")
        if path:
            self.open_right_file(path)

    def _on_swap(self):
        if self._buf_left.size() == 0 and self._buf_right.size() == 0:
            return
        # Swap buffers + path labels
        self._buf_left, self._buf_right = self._buf_right, self._buf_left
        self._hex_left.set_buffer(self._buf_left)
        self._hex_right.set_buffer(self._buf_right)
        left_text = self._path_left_label.text().replace("left:", "right:")
        right_text = self._path_right_label.text().replace("right:", "left:")
        self._path_left_label.setText(right_text.replace("left:", "left:"))
        self._path_right_label.setText(left_text.replace("right:", "right:"))
        # Tooltips
        lt = self._path_left_label.toolTip()
        rt = self._path_right_label.toolTip()
        self._path_left_label.setToolTip(rt)
        self._path_right_label.setToolTip(lt)
        self._maybe_compute_diff()

    def _on_next_diff(self):
        if not self._diff or not self._diff.regions:
            return
        cur = self._hex_left.selection_model.cursor
        target = self._diff.next_diff(cur)
        if target is not None:
            self._navigate_both(target)

    def _on_prev_diff(self):
        if not self._diff or not self._diff.regions:
            return
        cur = self._hex_left.selection_model.cursor
        target = self._diff.prev_diff(cur)
        if target is not None:
            self._navigate_both(target)

    def _navigate_both(self, offset: int):
        # Use a length of 1 for navigation; the diff highlighting shows the rest
        self._hex_left.navigate_to_offset(offset, 1)
        self._hex_right.navigate_to_offset(offset, 1)

    def _on_cursor_moved(self, offset: int):
        self._status_pos.setText(f"Offset: 0x{offset:08X} ({offset:,})")

    # ── Sync helpers ───────────────────────────────────────────────

    def _sync_scroll(self, target_widget: HexWidget, value: int):
        if self._syncing_scroll:
            return
        self._syncing_scroll = True
        try:
            target_widget.verticalScrollBar().setValue(value)
        finally:
            self._syncing_scroll = False

    def _mirror_cursor(self, target_widget: HexWidget, offset: int):
        # Move the other view's cursor without recursing
        if self._syncing_scroll:
            return
        # Block signals on the target so the cursor change doesn't bounce back
        target_widget.blockSignals(True)
        try:
            target_widget.navigate_to_offset(offset)
        finally:
            target_widget.blockSignals(False)

    # ── Diff computation ───────────────────────────────────────────

    def _maybe_compute_diff(self):
        """Compute the diff if both files are loaded."""
        if self._buf_left.size() == 0 or self._buf_right.size() == 0:
            self._hex_left.clear_diff_regions()
            self._hex_right.clear_diff_regions()
            self._diff = None
            self._status_summary.setText(
                "Open both files to compute the diff")
            return
        self._recompute_diff()

    def _recompute_diff(self):
        if self._buf_left.size() == 0 or self._buf_right.size() == 0:
            return
        self._diff = BinaryDiffModel(self._buf_left, self._buf_right)
        self._hex_left.set_diff_regions(self._diff.regions)
        self._hex_right.set_diff_regions(self._diff.regions)
        self._status_summary.setText(self._diff.summary())
