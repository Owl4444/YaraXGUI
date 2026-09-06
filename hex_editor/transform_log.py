# -*- coding: utf-8 -*-
"""Dock widget showing the transform history + undo/redo."""

from __future__ import annotations

from dataclasses import dataclass, field

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                               QLabel, QTableWidget, QTableWidgetItem,
                               QHeaderView, QAbstractItemView)

from .transforms import RecipeStep


@dataclass
class TransformLogEntry:
    """A single applied recipe, with enough state to undo and redo.

    ``snapshots`` stores the ORIGINAL bytes of each affected range in
    **apply order** (reverse offset — highest first), paired with
    ``new_lengths`` which gives the post-recipe length of each range.
    """
    timestamp: str
    op_name: str            # e.g. "Base64 decode \u2192 AES decrypt"
    scope_label: str
    params_label: str
    # (offset, original_bytes) in apply order (reverse-offset).
    snapshots: list[tuple[int, bytes]] = field(default_factory=list)
    new_lengths: list[int] = field(default_factory=list)
    # Full recipe so redo can re-apply without re-opening the dialog.
    steps: list[RecipeStep] = field(default_factory=list)

    def affected_count(self) -> int:
        return sum(len(b) for _, b in self.snapshots)


class TransformLogWidget(QWidget):
    """Log table + toolbar for applied transforms."""

    undo_requested = Signal()
    redo_requested = Signal()
    clear_requested = Signal()
    navigate_requested = Signal(int, int)   # offset, length
    modify_requested = Signal(int)          # row index of entry to edit

    _COLUMNS = ["Time", "Recipe", "Scope", "Params", "Bytes"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._entries: list[TransformLogEntry] = []
        self._redo_stack: list[TransformLogEntry] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Toolbar row
        bar = QHBoxLayout()
        self._undo_btn = QPushButton("Undo")
        self._undo_btn.clicked.connect(self.undo_requested.emit)
        bar.addWidget(self._undo_btn)

        self._redo_btn = QPushButton("Redo")
        self._redo_btn.clicked.connect(self.redo_requested.emit)
        bar.addWidget(self._redo_btn)

        self._clear_btn = QPushButton("Clear Log")
        self._clear_btn.clicked.connect(self.clear_requested.emit)
        bar.addWidget(self._clear_btn)

        bar.addStretch(1)

        self._status = QLabel("0 transforms applied")
        self._status.setStyleSheet("color: gray;")
        bar.addWidget(self._status)
        layout.addLayout(bar)

        # Table
        self._table = QTableWidget(0, len(self._COLUMNS))
        self._table.setHorizontalHeaderLabels(self._COLUMNS)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.itemDoubleClicked.connect(self._on_row_double_clicked)

        mono = QFont("Cascadia Code", 9)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self._table.setFont(mono)

        # Explicit high-contrast header styling using palette roles.
        # This overrides anything the global QSS may have left unreadable
        # and adapts automatically to whatever Qt palette is in effect.
        self._table.horizontalHeader().setStyleSheet("""
            QHeaderView::section {
                background-color: palette(button);
                color: palette(button-text);
                padding: 5px 8px;
                border: none;
                border-right: 1px solid palette(mid);
                border-bottom: 2px solid palette(highlight);
                font-weight: bold;
            }
            QHeaderView::section:hover {
                background-color: palette(light);
            }
        """)

        layout.addWidget(self._table, 1)

        self._refresh_buttons()

    # ── Undo stack API ──────────────────────────────────────────

    def entries(self) -> list[TransformLogEntry]:
        return list(self._entries)

    def add_entry(self, entry: TransformLogEntry):
        self._entries.append(entry)
        self._redo_stack.clear()
        self._append_row(entry)
        self._refresh_status()
        self._refresh_buttons()

    def pop_last(self) -> TransformLogEntry | None:
        if not self._entries:
            return None
        entry = self._entries.pop()
        self._redo_stack.append(entry)
        last_row = self._table.rowCount() - 1
        if last_row >= 0:
            self._table.removeRow(last_row)
        self._refresh_status()
        self._refresh_buttons()
        return entry

    def push_redo(self, entry: TransformLogEntry):
        """Replay an already-applied entry back onto the active stack."""
        self._entries.append(entry)
        if self._redo_stack and self._redo_stack[-1] is entry:
            self._redo_stack.pop()
        self._append_row(entry)
        self._refresh_status()
        self._refresh_buttons()

    def pop_redo(self) -> TransformLogEntry | None:
        if not self._redo_stack:
            return None
        return self._redo_stack[-1]

    def clear_all(self):
        self._entries.clear()
        self._redo_stack.clear()
        self._table.setRowCount(0)
        self._refresh_status()
        self._refresh_buttons()

    def has_entries(self) -> bool:
        return bool(self._entries)

    def has_redo(self) -> bool:
        return bool(self._redo_stack)

    # ── UI helpers ──────────────────────────────────────────────

    def _append_row(self, entry: TransformLogEntry):
        row = self._table.rowCount()
        self._table.insertRow(row)
        cols = [
            entry.timestamp,
            entry.op_name,
            entry.scope_label,
            entry.params_label,
            f"{entry.affected_count():,}",
        ]
        for col, text in enumerate(cols):
            item = QTableWidgetItem(text)
            if col == 1:
                item.setToolTip(entry.op_name)
            elif col == 3:
                item.setToolTip(entry.params_label)
            self._table.setItem(row, col, item)
        self._table.scrollToBottom()

    def _refresh_status(self):
        n = len(self._entries)
        r = len(self._redo_stack)
        parts = [f"{n} transform{'s' if n != 1 else ''} applied"]
        if r:
            parts.append(f"{r} in redo")
        self._status.setText(" \u00b7 ".join(parts))

    def _refresh_buttons(self):
        self._undo_btn.setEnabled(bool(self._entries))
        self._redo_btn.setEnabled(bool(self._redo_stack))
        self._clear_btn.setEnabled(bool(self._entries) or bool(self._redo_stack))

    def _on_row_double_clicked(self, item: QTableWidgetItem):
        row = item.row()
        if row < 0 or row >= len(self._entries):
            return
        # Double-click → request to modify the recipe.  The window decides
        # whether the entry is editable (only the most-recent one is) and
        # opens the dialog if so.
        self.modify_requested.emit(row)

    # ── Replace-in-place (used by the modify flow) ──────────────────

    def replace_entry(self, index: int, new_entry: TransformLogEntry):
        """Swap one entry for another and refresh just that row."""
        if index < 0 or index >= len(self._entries):
            return
        self._entries[index] = new_entry
        # Modifying invalidates redo history downstream of this entry.
        self._redo_stack.clear()
        cols = [
            new_entry.timestamp,
            new_entry.op_name,
            new_entry.scope_label,
            new_entry.params_label,
            f"{new_entry.affected_count():,}",
        ]
        for col, text in enumerate(cols):
            item = QTableWidgetItem(text)
            if col == 1:
                item.setToolTip(new_entry.op_name)
            elif col == 3:
                item.setToolTip(new_entry.params_label)
            self._table.setItem(index, col, item)
        self._refresh_status()
        self._refresh_buttons()
