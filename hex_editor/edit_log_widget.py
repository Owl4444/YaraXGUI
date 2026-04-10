# -*- coding: utf-8 -*-
"""Edit log dock widget — table view of all byte edits.

Shows every edit made to the hex buffer with offset, old bytes, new
bytes, and description.  Allows navigating to the edit offset and
undoing back to any point.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                               QTableWidget, QTableWidgetItem,
                               QHeaderView, QAbstractItemView,
                               QPushButton, QLabel)

from .edit_controller import EditCommand


class EditLogWidget(QWidget):
    """Dock content showing all byte edits in a table.

    Signals:
        navigate_requested(int, int): jump to (offset, length)
        undo_to_requested(int): undo back to entry index (exclusive)
    """

    navigate_requested = Signal(int, int)
    undo_to_requested = Signal(int)  # undo until stack has this many entries

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(2)

        # Header row
        header = QHBoxLayout()
        header.addWidget(QLabel("Edit History"))
        header.addStretch()

        self._count_label = QLabel("0 edits")
        header.addWidget(self._count_label)

        self._btn_undo_selected = QPushButton("Undo to Here")
        self._btn_undo_selected.setToolTip(
            "Undo all edits from the selected row onwards (inclusive)")
        self._btn_undo_selected.setEnabled(False)
        self._btn_undo_selected.clicked.connect(self._on_undo_to_selected)
        header.addWidget(self._btn_undo_selected)

        layout.addLayout(header)

        # Table
        self._table = QTableWidget()
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels([
            "#", "Offset", "Old", "New", "Description"
        ])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Fixed)
        self._table.setColumnWidth(0, 36)
        self._table.setColumnWidth(1, 85)
        self._table.setColumnWidth(2, 110)
        self._table.setColumnWidth(3, 110)
        self._table.verticalHeader().setVisible(False)
        self._table.verticalHeader().setDefaultSectionSize(20)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.doubleClicked.connect(self._on_double_click)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self._table)

    def refresh(self, commands: list[EditCommand]):
        """Rebuild the table from the edit controller's history."""
        self._table.setRowCount(0)
        self._table.setRowCount(len(commands))

        modified_color = QColor("#e05050")
        insert_color = QColor("#50a050")
        delete_color = QColor("#a0a050")

        total_bytes = 0
        for i, cmd in enumerate(commands):
            n = max(len(cmd.old_bytes), len(cmd.new_bytes))
            total_bytes += n

            # #
            idx_item = QTableWidgetItem(str(i + 1))
            idx_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(i, 0, idx_item)

            # Offset — show range if the edit spans more than 1 byte
            if n > 1:
                end = cmd.offset + n - 1
                off_text = f"0x{cmd.offset:08X}\u20130x{end:08X}"
            else:
                off_text = f"0x{cmd.offset:08X}"
            off_item = QTableWidgetItem(off_text)
            # Store raw offset + length for navigation
            off_item.setData(Qt.ItemDataRole.UserRole, (cmd.offset, n))
            self._table.setItem(i, 1, off_item)

            # Old bytes (truncate long ones)
            old_hex = _format_bytes(cmd.old_bytes)
            old_item = QTableWidgetItem(old_hex)
            old_item.setToolTip(
                _format_bytes(cmd.old_bytes, max_display=64)
                if cmd.old_bytes else "")
            self._table.setItem(i, 2, old_item)

            # New bytes
            new_hex = _format_bytes(cmd.new_bytes)
            new_item = QTableWidgetItem(new_hex)
            new_item.setToolTip(
                _format_bytes(cmd.new_bytes, max_display=64)
                if cmd.new_bytes else "")
            if cmd.size_changed and not cmd.new_bytes:
                new_item.setForeground(delete_color)
            elif cmd.size_changed and not cmd.old_bytes:
                new_item.setForeground(insert_color)
            else:
                new_item.setForeground(modified_color)
            self._table.setItem(i, 3, new_item)

            # Description
            desc_item = QTableWidgetItem(cmd.description)
            self._table.setItem(i, 4, desc_item)

        self._count_label.setText(
            f"{len(commands)} edit(s), {total_bytes} byte(s) changed")
        if commands:
            self._table.scrollToBottom()

    def _on_double_click(self, index):
        """Navigate to the offset of the double-clicked edit and select the range."""
        row = index.row()
        off_item = self._table.item(row, 1)
        if off_item:
            data = off_item.data(Qt.ItemDataRole.UserRole)
            if data:
                offset, length = data
                self.navigate_requested.emit(offset, length)
            else:
                # Fallback: parse from text
                text = off_item.text().split("\u2013")[0]
                try:
                    offset = int(text, 16)
                    self.navigate_requested.emit(offset, 1)
                except ValueError:
                    pass

    def _on_selection_changed(self):
        rows = self._table.selectionModel().selectedRows()
        self._btn_undo_selected.setEnabled(len(rows) > 0)

    def _on_undo_to_selected(self):
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        # Undo everything from this row onwards
        self.undo_to_requested.emit(row)


def _format_bytes(data: bytes, max_display: int = 12) -> str:
    """Format bytes for table display, truncating with ellipsis."""
    if not data:
        return "(empty)"
    hex_str = " ".join(f"{b:02X}" for b in data[:max_display])
    if len(data) > max_display:
        hex_str += f" ... (+{len(data) - max_display})"
    return hex_str
