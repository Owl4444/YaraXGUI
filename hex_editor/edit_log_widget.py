# -*- coding: utf-8 -*-
"""Edit log dock widget — table view of all byte edits.

Shows every edit made to the hex buffer with offset, old bytes, new
bytes, and description.  Each row reflects the *current* buffer state:
edits that were swallowed by a later delete are marked "(deleted)" and
double-clicking opens a diff popup that shows the change in context.
"""

from __future__ import annotations

import html as _html

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                               QTableWidget, QTableWidgetItem,
                               QHeaderView, QAbstractItemView,
                               QPushButton, QLabel, QDialog,
                               QTextEdit, QDialogButtonBox)

from .edit_controller import HistoryEntry
from .hex_data_buffer import HexDataBuffer


# ── Colour constants for highlighting ──────────────────────────────

_CLR_EDIT = "#e05050"      # red — edited bytes
_CLR_EDIT_BG = "#3a1818"   # subtle dark-red bg for edited byte cells
_CLR_CONTEXT = "#888888"   # gray — context bytes
_CLR_OFFSET = "#6a9955"    # green — offset gutter


class EditLogWidget(QWidget):
    """Dock content showing all byte edits in a table.

    Signals:
        navigate_requested(int, int): jump to (offset, length)
        undo_to_requested(int): undo back to entry index (exclusive)
    """

    navigate_requested = Signal(int, int)
    undo_to_requested = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._entries: list[HistoryEntry] = []
        self._buffer: HexDataBuffer | None = None

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
        self._table.setToolTip("Double-click to view the edit diff in context.")
        layout.addWidget(self._table)

    def set_buffer(self, buf: HexDataBuffer | None):
        self._buffer = buf

    def refresh(self, entries: list[HistoryEntry]):
        """Rebuild the table from enriched history entries."""
        self._entries = list(entries)
        self._table.setRowCount(0)
        self._table.setRowCount(len(entries))

        modified_color = QColor("#e05050")
        insert_color = QColor("#50a050")
        delete_color = QColor("#a0a050")
        dead_color = QColor("#888888")

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

            # Offset column
            off_text, off_tooltip = _format_offset_cell(entry)
            off_item = QTableWidgetItem(off_text)
            off_item.setToolTip(off_tooltip)
            if is_dead:
                off_item.setForeground(dead_color)
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

    def _on_double_click(self, index):
        """Always show the diff dialog; add Navigate button for alive entries."""
        row = index.row()
        if not (0 <= row < len(self._entries)):
            return
        entry = self._entries[row]
        dlg = EditDiffDialog(entry, self._buffer, self)
        dlg.navigate_requested.connect(self.navigate_requested.emit)
        dlg.exec()

    def _on_selection_changed(self):
        rows = self._table.selectionModel().selectedRows()
        self._btn_undo_selected.setEnabled(len(rows) > 0)

    def _on_undo_to_selected(self):
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        self.undo_to_requested.emit(rows[0].row())


# ── Helpers ────────────────────────────────────────────────────────


def _format_bytes(data: bytes, max_display: int = 12) -> str:
    if not data:
        return "(empty)"
    hex_str = " ".join(f"{b:02X}" for b in data[:max_display])
    if len(data) > max_display:
        hex_str += f" ... (+{len(data) - max_display})"
    return hex_str


def _format_offset_cell(entry: HistoryEntry) -> tuple[str, str]:
    cmd = entry.cmd
    if entry.is_delete:
        return ("\u2014 deleted \u2014",
                f"Was at 0x{cmd.offset:08X}, "
                f"{len(cmd.old_bytes)} byte(s) removed.\n"
                f"Double-click to view the deleted bytes.")
    if entry.is_consumed:
        return ("\u2014 consumed \u2014",
                f"Was at 0x{cmd.offset:08X}, "
                f"now removed by a later delete.\n"
                f"Double-click to view the original edit.")
    cur_off = entry.current_offset
    cur_len = entry.current_length
    if cur_len > 1:
        cur_text = f"0x{cur_off:08X}\u20130x{cur_off + cur_len - 1:08X}"
    else:
        cur_text = f"0x{cur_off:08X}"
    if cur_off != cmd.offset:
        tooltip = (f"Currently at 0x{cur_off:08X} (shifted from "
                   f"original 0x{cmd.offset:08X})")
    else:
        tooltip = f"At 0x{cur_off:08X}"
    return (cur_text, tooltip)


# ── Hex dump renderer with per-byte highlighting ───────────────────


def _hexdump_html(data: bytes, base_offset: int,
                  highlight_offsets: set[int],
                  bpl: int = 16, max_bytes: int = 512) -> str:
    """Render a hex+ASCII dump as HTML ``<pre>`` content.

    Bytes whose *absolute* offset is in *highlight_offsets* are rendered
    in bold red; the rest are gray (context).  Alignment is preserved
    because the ``<span>`` tags add no visible characters inside the
    monospace ``<pre>`` block.
    """
    truncated = len(data) > max_bytes
    view = data[:max_bytes]
    lines: list[str] = []
    for i in range(0, len(view), bpl):
        off = base_offset + i
        chunk = view[i:i + bpl]
        hex_cells: list[str] = []
        ascii_cells: list[str] = []
        for j, b in enumerate(chunk):
            abs_off = off + j
            h = f"{b:02X}"
            ch = chr(b) if 32 <= b <= 126 else "."
            if abs_off in highlight_offsets:
                hex_cells.append(
                    f'<span style="color:{_CLR_EDIT};'
                    f'background:{_CLR_EDIT_BG};font-weight:bold">{h}</span>')
                ascii_cells.append(
                    f'<span style="color:{_CLR_EDIT};'
                    f'background:{_CLR_EDIT_BG};font-weight:bold">'
                    f'{_html.escape(ch)}</span>')
            else:
                hex_cells.append(f'<span style="color:{_CLR_CONTEXT}">{h}</span>')
                ascii_cells.append(
                    f'<span style="color:{_CLR_CONTEXT}">{_html.escape(ch)}</span>')
        # Pad short last line
        while len(hex_cells) < bpl:
            hex_cells.append("  ")
            ascii_cells.append(" ")

        hex_str = " ".join(hex_cells)
        ascii_str = "".join(ascii_cells)
        off_str = f'<span style="color:{_CLR_OFFSET}">{off:08X}</span>'
        lines.append(f"{off_str}  {hex_str}  {ascii_str}")
    if truncated:
        lines.append(f'<span style="color:{_CLR_CONTEXT}">'
                     f"... (+{len(data) - max_bytes} more bytes)</span>")
    return "\n".join(lines)


# ── Diff dialog ────────────────────────────────────────────────────

CONTEXT_LINES = 4  # lines of 16 bytes shown before/after the edit


class EditDiffDialog(QDialog):
    """Modal dialog showing the edit in context with highlighted bytes.

    For alive entries: shows the current buffer state around the edit,
    with the changed bytes highlighted in red.
    For dead entries: shows the original before/after hex dumps.
    Always includes a Navigate button for alive entries.
    """

    navigate_requested = Signal(int, int)

    def __init__(self, entry: HistoryEntry,
                 buffer: HexDataBuffer | None = None,
                 parent=None):
        super().__init__(parent)
        self._entry = entry
        self.setWindowTitle("Edit Diff")
        self.resize(720, 480)

        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        # Header
        header_label = QLabel(self._make_header(entry))
        header_label.setStyleSheet("font-weight: bold; padding: 4px;")
        header_label.setWordWrap(True)
        layout.addWidget(header_label)

        # Rich-text hex view
        self._text = QTextEdit()
        self._text.setReadOnly(True)
        font = QFont()
        font.setFamilies(["Cascadia Mono", "Consolas", "Courier New", "monospace"])
        font.setPointSize(10)
        font.setFixedPitch(True)
        self._text.setFont(font)
        self._text.setHtml(self._build_html(entry, buffer))
        layout.addWidget(self._text, 1)

        # Buttons
        btn_layout = QHBoxLayout()
        is_alive = (entry.current_offset is not None
                    and not entry.is_delete
                    and not entry.is_consumed)
        if is_alive:
            nav_btn = QPushButton("Navigate to Current Location")
            nav_btn.setToolTip(
                f"Jump the hex view to 0x{entry.current_offset:X}")
            nav_btn.clicked.connect(self._on_navigate)
            btn_layout.addWidget(nav_btn)
        btn_layout.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

    def _on_navigate(self):
        e = self._entry
        if e.current_offset is not None:
            self.navigate_requested.emit(e.current_offset, e.current_length)
            self.accept()

    # ── HTML builders ──────────────────────────────────────────────

    @staticmethod
    def _make_header(entry: HistoryEntry) -> str:
        cmd = entry.cmd
        if entry.is_delete:
            n = len(cmd.old_bytes)
            return (f"\u2716 Delete: {n} byte(s) at "
                    f"0x{cmd.offset:08X}\u20130x{cmd.offset + n - 1:08X}")
        if entry.is_consumed:
            return (f"\u26D4 Edit consumed: {cmd.description}")
        if (entry.current_offset is not None
                and entry.current_offset != cmd.offset):
            return (f"{cmd.description}  "
                    f"(shifted to 0x{entry.current_offset:08X})")
        return cmd.description

    @staticmethod
    def _build_html(entry: HistoryEntry,
                    buffer: HexDataBuffer | None) -> str:
        cmd = entry.cmd
        bpl = 16
        parts: list[str] = []

        is_alive = (entry.current_offset is not None
                    and not entry.is_delete
                    and not entry.is_consumed
                    and buffer is not None)

        if is_alive:
            # ── Alive: show current buffer with context + highlights ─
            cur_off = entry.current_offset
            cur_len = entry.current_length
            start_line = max(0, (cur_off // bpl) - CONTEXT_LINES)
            end_byte = cur_off + cur_len
            end_line = ((end_byte - 1) // bpl) + CONTEXT_LINES + 1
            start = start_line * bpl
            end = min(end_line * bpl, buffer.size())
            data = buffer.read(start, end - start)
            hl = set(range(cur_off, cur_off + cur_len))

            parts.append(
                '<span style="color:#aaa">Current buffer state '
                f'({CONTEXT_LINES} lines of context, '
                'changed bytes in <span style="color:#e05050;font-weight:bold">'
                'red</span>):</span>')
            parts.append(f'<pre>{_hexdump_html(data, start, hl)}</pre>')

            # Also show the before state for comparison
            if cmd.old_bytes:
                parts.append(
                    '<br><span style="color:#aaa">Previous bytes at this '
                    'location:</span>')
                hl_before = set(range(cmd.offset,
                                      cmd.offset + len(cmd.old_bytes)))
                parts.append(
                    f'<pre>{_hexdump_html(cmd.old_bytes, cmd.offset, hl_before)}</pre>')
        else:
            # ── Dead: show before/after without buffer context ──────
            if entry.is_consumed:
                parts.append(
                    '<span style="color:#aaa">This edit\'s bytes were '
                    'consumed by a later delete. Showing the original '
                    'before/after:</span><br>')

            if cmd.old_bytes:
                hl_old = set(range(cmd.offset,
                                   cmd.offset + len(cmd.old_bytes)))
                parts.append(
                    f'<span style="color:#aaa">'
                    f'\u2500\u2500\u2500 BEFORE '
                    f'({len(cmd.old_bytes)} bytes) '
                    f'\u2500\u2500\u2500</span>')
                parts.append(
                    f'<pre>{_hexdump_html(cmd.old_bytes, cmd.offset, hl_old)}</pre>')

            if cmd.new_bytes:
                hl_new = set(range(cmd.offset,
                                   cmd.offset + len(cmd.new_bytes)))
                parts.append(
                    f'<span style="color:#aaa">'
                    f'+++ AFTER '
                    f'({len(cmd.new_bytes)} bytes) '
                    f'+++</span>')
                parts.append(
                    f'<pre>{_hexdump_html(cmd.new_bytes, cmd.offset, hl_new)}</pre>')
            elif entry.is_delete:
                parts.append(
                    '<pre><span style="color:#a0a050">'
                    '(bytes removed from buffer)</span></pre>')

        return "\n".join(parts)
