# -*- coding: utf-8 -*-
"""YARA rule browser widget with folder tree, file preview tooltips,
and load-on-double-click.

Replaces the flat QFileDialog with a persistent, explorable view of
a YARA rule directory.  The user picks a root folder once, then
navigates the tree freely.  Hovering any ``.yar`` / ``.yara`` file
shows a rich tooltip with the first ~40 lines of the rule.  Double-
clicking loads the file into the editor.
"""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import (Qt, Signal, QDir, QModelIndex, QSortFilterProxyModel,
                            QFileSystemWatcher, QTimer)
from PySide6.QtGui import QFont, QIcon, QAction
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTreeView,
                               QFileSystemModel, QLabel, QPushButton,
                               QToolButton, QFileDialog, QHeaderView,
                               QAbstractItemView, QMenu, QToolTip,
                               QApplication, QLineEdit)


_YARA_EXTENSIONS = {".yar", ".yara", ".yarax"}

# Maximum bytes to read for tooltip preview (keeps tooltips snappy)
_PREVIEW_MAX_BYTES = 4096
_PREVIEW_MAX_LINES = 40


class _YaraFileFilterProxy(QSortFilterProxyModel):
    """Show only directories and YARA rule files."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._show_all_files = False

    def set_show_all_files(self, show: bool):
        self._show_all_files = show
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model = self.sourceModel()
        if model is None:
            return False
        idx = model.index(source_row, 0, source_parent)
        if not idx.isValid():
            return False

        # Always show directories so the tree is navigable
        if model.isDir(idx):
            return True

        if self._show_all_files:
            return True

        # Only show YARA files
        name = model.fileName(idx)
        _, ext = os.path.splitext(name)
        return ext.lower() in _YARA_EXTENSIONS


def _read_preview(filepath: str) -> str:
    """Read the first N lines of a file for tooltip display."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines: list[str] = []
            total = 0
            for line in f:
                total += len(line)
                lines.append(line.rstrip("\n\r"))
                if len(lines) >= _PREVIEW_MAX_LINES or total >= _PREVIEW_MAX_BYTES:
                    break
        text = "\n".join(lines)
        if total >= _PREVIEW_MAX_BYTES or len(lines) >= _PREVIEW_MAX_LINES:
            text += "\n..."
        return text
    except Exception as e:
        return f"(cannot read: {e})"


def _preview_to_rich_tooltip(filepath: str, preview: str) -> str:
    """Format a preview string as a rich HTML tooltip."""
    import html
    name = Path(filepath).name
    escaped = html.escape(preview)

    # Minimal syntax colouring for YARA keywords
    for kw in ("rule ", "meta:", "strings:", "condition:",
               "import ", "include ", "private ", "global "):
        escaped = escaped.replace(
            html.escape(kw),
            f'<span style="color:#2070c0;font-weight:bold;">{html.escape(kw)}</span>')

    return (
        f'<div style="max-width:560px;">'
        f'<b>{html.escape(name)}</b><br>'
        f'<hr>'
        f'<pre style="font-family:Consolas,Courier New,monospace;'
        f'font-size:9pt;margin:4px 0;white-space:pre-wrap;">'
        f'{escaped}</pre>'
        f'</div>'
    )


def _count_yara_files(dirpath: str) -> int:
    """Quickly count .yar/.yara files under a directory (non-recursive top level)."""
    try:
        return sum(
            1 for f in os.scandir(dirpath)
            if f.is_file() and os.path.splitext(f.name)[1].lower() in _YARA_EXTENSIONS
        )
    except OSError:
        return 0


class YaraRuleBrowser(QWidget):
    """Folder-tree browser for YARA rule files.

    Signals:
        file_requested(str): emitted when user double-clicks a .yar file
            — the main window should load it into the editor.
        files_requested(list[str]): emitted when user wants to load all
            rules from a folder.
    """

    file_requested = Signal(str)       # single file path
    files_requested = Signal(list)     # list of file paths

    def __init__(self, parent=None):
        super().__init__(parent)
        self._root_path: str = ""
        self._last_dir: str = str(Path.home())

        # ── Layout ─────────────────────────────────────────────────
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        # Top bar: [Set Folder] [path label] [filter field]
        top_bar = QHBoxLayout()
        top_bar.setSpacing(4)

        self._btn_set_folder = QToolButton(self)
        self._btn_set_folder.setText("Set Folder")
        self._btn_set_folder.setToolTip("Choose root folder containing YARA rules")
        self._btn_set_folder.clicked.connect(self._on_pick_folder)
        top_bar.addWidget(self._btn_set_folder)

        self._btn_open_file = QToolButton(self)
        self._btn_open_file.setText("Open File")
        self._btn_open_file.setToolTip("Open a single YARA file (Ctrl+O shortcut)")
        self._btn_open_file.clicked.connect(self._on_open_single_file)
        top_bar.addWidget(self._btn_open_file)

        self._path_label = QLabel("No folder selected")
        self._path_label.setStyleSheet("color: gray; font-style: italic;")
        self._path_label.setToolTip("Current YARA rules folder")
        top_bar.addWidget(self._path_label, 1)

        layout.addLayout(top_bar)

        # Quick filter
        filter_row = QHBoxLayout()
        filter_row.setSpacing(4)
        filter_row.addWidget(QLabel("Filter:"))
        self._filter_edit = QLineEdit(self)
        self._filter_edit.setPlaceholderText("Type to filter rule names...")
        self._filter_edit.setClearButtonEnabled(True)
        self._filter_edit.textChanged.connect(self._on_filter_changed)
        filter_row.addWidget(self._filter_edit, 1)
        layout.addLayout(filter_row)

        # ── File system model + proxy ──────────────────────────────
        self._fs_model = QFileSystemModel(self)
        self._fs_model.setReadOnly(True)
        self._fs_model.setFilter(
            QDir.Filter.AllDirs | QDir.Filter.Files | QDir.Filter.NoDotAndDotDot)
        self._fs_model.setNameFilterDisables(False)

        self._proxy = _YaraFileFilterProxy(self)
        self._proxy.setSourceModel(self._fs_model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._proxy.setRecursiveFilteringEnabled(True)

        # ── Tree view ──────────────────────────────────────────────
        self._tree = QTreeView(self)
        self._tree.setModel(self._proxy)
        self._tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tree.setSortingEnabled(True)
        self._tree.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self._tree.setAlternatingRowColors(True)
        self._tree.setUniformRowHeights(True)
        self._tree.setMouseTracking(True)  # needed for hover tooltips
        self._tree.setAnimated(True)

        # Column visibility: show Name + Size, hide Type + Date Modified
        header = self._tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._tree.setColumnHidden(2, True)  # Type
        self._tree.setColumnHidden(3, True)  # Date Modified

        # Signals
        self._tree.doubleClicked.connect(self._on_double_click)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_context_menu)

        layout.addWidget(self._tree, 1)

        # ── Status label ───────────────────────────────────────────
        self._status_label = QLabel("")
        self._status_label.setStyleSheet("color: gray; font-size: 9pt;")
        layout.addWidget(self._status_label)

        # Debounce timer for filter
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(200)
        self._filter_timer.timeout.connect(self._apply_filter)

        # Tooltip cache to avoid re-reading files on every hover
        self._tooltip_cache: dict[str, str] = {}

    # ── Public API ─────────────────────────────────────────────────

    def set_root(self, folder: str):
        """Set the root folder and populate the tree."""
        folder = str(Path(folder).resolve())
        if not Path(folder).is_dir():
            return
        self._root_path = folder
        self._last_dir = folder
        root_idx = self._fs_model.setRootPath(folder)
        proxy_root = self._proxy.mapFromSource(root_idx)
        self._tree.setRootIndex(proxy_root)
        self._tree.expand(proxy_root)

        # Truncate long paths for the label
        display = folder
        if len(display) > 60:
            display = "..." + display[-57:]
        self._path_label.setText(display)
        self._path_label.setToolTip(folder)
        self._path_label.setStyleSheet("")

        self._tooltip_cache.clear()
        self._update_status()

    def root_path(self) -> str:
        return self._root_path

    def last_dir(self) -> str:
        return self._last_dir

    def set_last_dir(self, d: str):
        self._last_dir = d

    # ── Tooltip on hover ───────────────────────────────────────────

    def _get_file_tooltip(self, filepath: str) -> str:
        """Return cached rich tooltip HTML for a YARA file."""
        if filepath in self._tooltip_cache:
            return self._tooltip_cache[filepath]
        preview = _read_preview(filepath)
        html = _preview_to_rich_tooltip(filepath, preview)
        self._tooltip_cache[filepath] = html
        return html

    def event(self, ev):
        """Override to intercept ToolTip events on the tree viewport."""
        if ev.type() == ev.Type.ToolTip:
            # The tree view handles its own tooltips, so we override
            # via the viewportEvent approach below instead.
            pass
        return super().event(ev)

    # We install ourselves as viewport event filter in showEvent
    def showEvent(self, ev):
        super().showEvent(ev)
        self._tree.viewport().installEventFilter(self)

    def eventFilter(self, obj, ev):
        """Show rich YARA preview tooltips when hovering tree items."""
        if obj is self._tree.viewport() and ev.type() == ev.Type.ToolTip:
            pos = ev.pos()
            idx = self._tree.indexAt(pos)
            if idx.isValid():
                source_idx = self._proxy.mapToSource(idx)
                filepath = self._fs_model.filePath(source_idx)
                if filepath and Path(filepath).is_file():
                    ext = Path(filepath).suffix.lower()
                    if ext in _YARA_EXTENSIONS:
                        tooltip = self._get_file_tooltip(filepath)
                        QToolTip.showText(ev.globalPos(), tooltip, self._tree)
                        return True
                    else:
                        QToolTip.showText(ev.globalPos(),
                                          f"{Path(filepath).name}\n{filepath}",
                                          self._tree)
                        return True
                elif filepath and Path(filepath).is_dir():
                    count = _count_yara_files(filepath)
                    tip = f"{Path(filepath).name}/\n{count} YARA file(s)"
                    QToolTip.showText(ev.globalPos(), tip, self._tree)
                    return True
            QToolTip.hideText()
            return True
        return super().eventFilter(obj, ev)

    # ── Slots ──────────────────────────────────────────────────────

    def _on_pick_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Select YARA rules folder", self._last_dir)
        if folder:
            self.set_root(folder)

    def _on_open_single_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open YARA rule", self._last_dir,
            "YARA files (*.yar *.yara);;All files (*)")
        if path:
            self._last_dir = str(Path(path).parent)
            self.file_requested.emit(path)

    def _on_double_click(self, proxy_idx: QModelIndex):
        source_idx = self._proxy.mapToSource(proxy_idx)
        filepath = self._fs_model.filePath(source_idx)
        if not filepath:
            return
        p = Path(filepath)
        if p.is_file() and p.suffix.lower() in _YARA_EXTENSIONS:
            self.file_requested.emit(filepath)
        elif p.is_dir():
            # Expand/collapse handled by tree itself; no action needed
            pass

    def _on_context_menu(self, pos):
        idx = self._tree.indexAt(pos)
        if not idx.isValid():
            return
        source_idx = self._proxy.mapToSource(idx)
        filepath = self._fs_model.filePath(source_idx)
        if not filepath:
            return

        menu = QMenu(self)
        p = Path(filepath)

        if p.is_file() and p.suffix.lower() in _YARA_EXTENSIONS:
            act_load = menu.addAction("Load into Editor")
            act_load.triggered.connect(lambda: self.file_requested.emit(filepath))

            act_copy = menu.addAction("Copy Path")
            act_copy.triggered.connect(
                lambda: QApplication.clipboard().setText(filepath))

            menu.addSeparator()
            act_preview = menu.addAction("Preview in Tooltip")
            act_preview.triggered.connect(
                lambda: QToolTip.showText(
                    self._tree.viewport().mapToGlobal(pos),
                    self._get_file_tooltip(filepath),
                    self._tree))

        elif p.is_dir():
            yara_files = sorted(
                str(f) for f in p.iterdir()
                if f.is_file() and f.suffix.lower() in _YARA_EXTENSIONS
            )
            act_load_all = menu.addAction(
                f"Load All Rules ({len(yara_files)} files)")
            act_load_all.setEnabled(len(yara_files) > 0)
            act_load_all.triggered.connect(
                lambda: self.files_requested.emit(yara_files))

            act_copy = menu.addAction("Copy Path")
            act_copy.triggered.connect(
                lambda: QApplication.clipboard().setText(filepath))

        if menu.actions():
            menu.exec(self._tree.viewport().mapToGlobal(pos))

    def _on_filter_changed(self, text: str):
        self._filter_timer.start()

    def _apply_filter(self):
        text = self._filter_edit.text().strip()
        if text:
            # Use name filter wildcards for the filesystem model
            patterns = [f"*{text}*"]
            self._fs_model.setNameFilters(patterns)
            self._fs_model.setNameFilterDisables(False)
        else:
            self._fs_model.setNameFilters([])
        self._update_status()

    def _update_status(self):
        if not self._root_path:
            self._status_label.setText("")
            return
        # Count visible files (quick approximation from top-level)
        try:
            count = sum(
                1 for f in Path(self._root_path).rglob("*")
                if f.is_file() and f.suffix.lower() in _YARA_EXTENSIONS
            )
            self._status_label.setText(f"{count} YARA rule file(s) found")
        except OSError:
            self._status_label.setText("")
