# -*- coding: utf-8 -*-
"""Edit log dock widget — table view of all byte edits.

Shows every edit made to the hex buffer with offset, old bytes, new
bytes, and description.  Each row reflects the *current* buffer state:
edits that were swallowed by a later delete are marked "(deleted)" and
double-clicking opens a diff popup instead of trying to navigate to a
nonexistent offset.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                               QTableWidget, QTableWidgetItem,
                               QHeaderView, QAbstractItemView,
                               QPushButton, QLabel, QDialog,
                               QPlainTextEdit, QDialogButtonBox)

from .edit_controller import HistoryEntry


class EditLogWidget(QWidget):
    """Dock content showing all byte edits in a table.

    Signals:
        navigate_requested(int, int): jump to (offset, length) — emitted
            only for edits whose bytes still exist in the current buffer.
        undo_to_requested(int): undo back to entry index (exclusive)
    """

    navigate_requested = Signal(int, int)
    undo_to_requested = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._entries: list[HistoryEntry] = []

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
        self._table.setColumnWidth(1, 130)
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
        self._table.setToolTip(
            "Double-click an entry to navigate to its bytes.\n"
            "Deleted entries open a diff popup instead.")
        layout.addWidget(self._table)

    def refresh(self, entries: list[HistoryEntry]):
        """Rebuild the table from enriched history entries."""
        self._entries = list(entries)
        self._table.setRowCount(0)
        self._table.setRowCount(len(entries))

        modified_color = QColor("#e05050")
        insert_color = QColor("#50a050")
        delete_color = QColor("#a0a050")
        dead_color = QColor("#888888")  # consumed / deleted entries

        total_bytes = 0
        for i, entry in enumerate(entries):
            cmd = entry.cmd
            n = max(len(cmd.old_bytes), len(cmd.new_bytes))
            total_bytes += n
            is_dead = entry.is_delete or entry.is_consumed

            # # column
            idx_item = QTableWidgetItem(str(i + 1))
            idx_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if is_dead:
                idx_item.setForeground(dead_color)
            self._table.setItem(i, 0, idx_item)

            # Offset column — use CURRENT offset, not original
            off_text, off_tooltip = self._format_offset_cell(entry)
            off_item = QTableWidgetItem(off_text)
            off_item.setToolTip(off_tooltip)
            if is_dead:
                off_item.setForeground(dead_color)
                # Italic for dead entries to make them visually distinct
                f = off_item.font()
                f.setItalic(True)
                off_item.setFont(f)
            self._table.setItem(i, 1, off_item)

            # Old bytes
            old_hex = _format_bytes(cmd.old_bytes)
            old_item = QTableWidgetItem(old_hex)
            old_item.setToolTip(
                _format_bytes(cmd.old_bytes, max_display=64)
                if cmd.old_bytes else "")
            if is_dead:
                old_item.setForeground(dead_color)
            self._table.setItem(i, 2, old_item)

            # New bytes
            new_hex = _format_bytes(cmd.new_bytes)
            new_item = QTableWidgetItem(new_hex)
            new_item.setToolTip(
                _format_bytes(cmd.new_bytes, max_display=64)
                if cmd.new_bytes else "")
            if is_dead:
                new_item.setForeground(dead_color)
            elif entry.is_delete:
                new_item.setForeground(delete_color)
            elif cmd.size_changed and not cmd.old_bytes:
                new_item.setForeground(insert_color)
            else:
                new_item.setForeground(modified_color)
            self._table.setItem(i, 3, new_item)

            # Description
            desc_text = cmd.description
            if entry.is_consumed:
                desc_text += "  (consumed by later delete)"
            elif entry.is_delete:
                desc_text += "  (bytes removed)"
            desc_item = QTableWidgetItem(desc_text)
            if is_dead:
                desc_item.setForeground(dead_color)
            self._table.setItem(i, 4, desc_item)

        self._count_label.setText(
            f"{len(entries)} edit(s), {total_bytes} byte(s) changed")
        if entries:
            self._table.scrollToBottom()

    @staticmethod
    def _format_offset_cell(entry: HistoryEntry) -> tuple[str, str]:
        """Return (display_text, tooltip) for the offset column."""
        cmd = entry.cmd
        if entry.is_delete:
            return (f"\u2014 deleted \u2014",
                    f"Was at 0x{cmd.offset:08X}, "
                    f"{len(cmd.old_bytes)} byte(s) removed.\n"
                    f"Double-click to view the deleted bytes.")
        if entry.is_consumed:
            return (f"\u2014 consumed \u2014",
                    f"Was at 0x{cmd.offset:08X}, "
                    f"now removed by a later delete.\n"
                    f"Double-click to view the original edit.")

        # Surviving — use CURRENT offset (may differ from cmd.offset if shifted)
        cur_off = entry.current_offset
        cur_len = entry.current_length
        if cur_len > 1:
            cur_text = f"0x{cur_off:08X}\u20130x{cur_off + cur_len - 1:08X}"
        else:
            cur_text = f"0x{cur_off:08X}"

        if cur_off != cmd.offset:
            tooltip = (f"Currently at 0x{cur_off:08X} (shifted from "
                       f"original 0x{cmd.offset:08X} by later inserts/deletes)")
        else:
            tooltip = f"At 0x{cur_off:08X}"
        return (cur_text, tooltip)

    def _on_double_click(self, index):
        """Navigate to current offset, or show diff popup if entry is dead."""
        row = index.row()
        if not (0 <= row < len(self._entries)):
            return
        entry = self._entries[row]

        if entry.is_delete or entry.is_consumed or entry.current_offset is None:
            # Bytes don't exist in the current buffer — show a diff popup
            dlg = EditDiffDialog(entry, self)
            dlg.exec()
        else:
            self.navigate_requested.emit(entry.current_offset, entry.current_length)

    def _on_selection_changed(self):
        rows = self._table.selectionModel().selectedRows()
        self._btn_undo_selected.setEnabled(len(rows) > 0)

    def _on_undo_to_selected(self):
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        self.undo_to_requested.emit(row)


# ── Helpers ────────────────────────────────────────────────────────


def _format_bytes(data: bytes, max_display: int = 12) -> str:
    """Format bytes for table display, truncating with ellipsis."""
    if not data:
        return "(empty)"
    hex_str = " ".join(f"{b:02X}" for b in data[:max_display])
    if len(data) > max_display:
        hex_str += f" ... (+{len(data) - max_display})"
    return hex_str


def _hexdump(data: bytes, base_offset: int = 0,
             max_bytes: int = 256) -> str:
    """Render bytes as a classic hex+ASCII dump for the diff dialog."""
    if not data:
        return "(empty)"
    truncated = len(data) > max_bytes
    view = data[:max_bytes]
    lines: list[str] = []
    for i in range(0, len(view), 16):
        chunk = view[i:i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk).ljust(48)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{base_offset + i:08X}  {hex_part}  {ascii_part}")
    if truncated:
        lines.append(f"... (+{len(data) - max_bytes} more bytes)")
    return "\n".join(lines)


# ── Diff dialog ────────────────────────────────────────────────────


class EditDiffDialog(QDialog):
    """Modal dialog showing the before/after bytes for a dead edit entry.

    Used when the user double-clicks an edit whose bytes no longer exist
    in the current buffer (e.g. a delete, or an overwrite that was later
    swallowed by a delete).  Showing the cursor position would be
    misleading, so we show the actual diff instead.
    """

    def __init__(self, entry: HistoryEntry, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Diff")
        self.resize(620, 440)

        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        # Header label
        header_text = self._format_header(entry)
        header_label = QLabel(header_text)
        header_label.setStyleSheet("font-weight: bold; padding: 4px;")
        header_label.setWordWrap(True)
        layout.addWidget(header_label)

        # Subtitle
        subtitle = self._format_subtitle(entry)
        if subtitle:
            sub_label = QLabel(subtitle)
            sub_label.setStyleSheet("color: #888; padding-left: 4px;")
            layout.addWidget(sub_label)

        # Diff text area
        self._text = QPlainTextEdit()
        self._text.setReadOnly(True)
        font = QFont()
        font.setFamilies(["Cascadia Mono", "Consolas", "Courier New", "monospace"])
        font.setPointSize(9)
        font.setFixedPitch(True)
        self._text.setFont(font)
        self._text.setPlainText(self._format_diff(entry))
        layout.addWidget(self._text, 1)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        button_box.rejected.connect(self.reject)
        button_box.accepted.connect(self.accept)
        layout.addWidget(button_box)

    @staticmethod
    def _format_header(entry: HistoryEntry) -> str:
        cmd = entry.cmd
        if entry.is_delete:
            n = len(cmd.old_bytes)
            return (f"\u2716 Delete: {n} byte(s) at "
                    f"0x{cmd.offset:08X}\u20130x{cmd.offset + n - 1:08X}")
        if entry.is_consumed:
            return (f"\u26D4 Edit consumed: original op at "
                    f"0x{cmd.offset:08X}, no longer in buffer")
        return cmd.description

    @staticmethod
    def _format_subtitle(entry: HistoryEntry) -> str:
        if entry.is_delete:
            return ("These bytes were removed from the buffer. "
                    "There is no current location to navigate to.")
        if entry.is_consumed:
            return ("This edit's bytes were swallowed by a later delete. "
                    "Showing the original before/after diff.")
        return ""

    @staticmethod
    def _format_diff(entry: HistoryEntry) -> str:
        cmd = entry.cmd
        sections: list[str] = []

        if cmd.old_bytes:
            sections.append(f"--- BEFORE ({len(cmd.old_bytes)} bytes) ---")
            sections.append(_hexdump(cmd.old_bytes, cmd.offset))

        if cmd.new_bytes:
            if sections:
                sections.append("")
            sections.append(f"+++ AFTER ({len(cmd.new_bytes)} bytes) +++")
            sections.append(_hexdump(cmd.new_bytes, cmd.offset))
        elif entry.is_delete:
            if sections:
                sections.append("")
            sections.append("+++ AFTER +++")
            sections.append("(bytes removed)")

        return "\n".join(sections)
