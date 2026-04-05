# -*- coding: utf-8 -*-
"""Search engine and dialog for the hex editor."""

import re
from typing import List, Tuple, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTabWidget,
                               QWidget, QLabel, QLineEdit, QCheckBox,
                               QPushButton, QTableWidget, QTableWidgetItem,
                               QHeaderView, QAbstractItemView, QMessageBox,
                               QProgressBar)

from .hex_data_buffer import HexDataBuffer

CHUNK_SIZE = 1024 * 1024  # 1 MB search chunks
OVERLAP = 4096


class HexSearchEngine:
    """Byte-level search engine with hex pattern, text, and regex support."""

    def __init__(self, buffer: HexDataBuffer):
        self._buffer = buffer

    # ── Hex pattern search ──────────────────────────────────────────

    def search_hex(self, pattern: str, start: int = 0, forward: bool = True) -> int:
        """Search for hex pattern like "4D 5A ?? 00". Returns offset or -1."""
        regex = self._hex_pattern_to_regex(pattern)
        if regex is None:
            return -1
        return self._search_regex_bytes(regex, start, forward)

    def find_all_hex(self, pattern: str) -> List[Tuple[int, int]]:
        """Find all hex pattern matches. Returns list of (offset, length)."""
        regex = self._hex_pattern_to_regex(pattern)
        if regex is None:
            return []
        return self._find_all_regex(regex)

    @staticmethod
    def _hex_pattern_to_regex(pattern: str) -> Optional[re.Pattern]:
        tokens = pattern.strip().split()
        if not tokens:
            return None
        parts = []
        for token in tokens:
            t = token.strip()
            if t in ("??", "?"):
                parts.append(".")
            else:
                try:
                    val = int(t, 16)
                    if not (0 <= val <= 255):
                        return None
                    parts.append(re.escape(bytes([val]).decode("latin-1")))
                except ValueError:
                    return None
        return re.compile("".join(parts).encode("latin-1"), re.DOTALL)

    # ── Text search ─────────────────────────────────────────────────

    def search_text(self, text: str, encoding: str = "ascii",
                    case_sensitive: bool = True,
                    start: int = 0, forward: bool = True) -> int:
        try:
            if encoding == "utf-16-le":
                needle = text.encode("utf-16-le")
            else:
                needle = text.encode("utf-8")
        except UnicodeEncodeError:
            return -1

        if not case_sensitive:
            regex = re.compile(re.escape(needle), re.IGNORECASE | re.DOTALL)
        else:
            regex = re.compile(re.escape(needle), re.DOTALL)
        return self._search_regex_bytes(regex, start, forward)

    def find_all_text(self, text: str, encoding: str = "ascii",
                      case_sensitive: bool = True) -> List[Tuple[int, int]]:
        try:
            if encoding == "utf-16-le":
                needle = text.encode("utf-16-le")
            else:
                needle = text.encode("utf-8")
        except UnicodeEncodeError:
            return []
        flags = re.DOTALL | (0 if case_sensitive else re.IGNORECASE)
        regex = re.compile(re.escape(needle), flags)
        return self._find_all_regex(regex)

    # ── Regex search ────────────────────────────────────────────────

    def search_regex(self, pattern: str, start: int = 0, forward: bool = True) -> int:
        try:
            regex = re.compile(pattern.encode("latin-1"), re.DOTALL)
        except re.error:
            return -1
        return self._search_regex_bytes(regex, start, forward)

    def find_all_regex(self, pattern: str) -> List[Tuple[int, int]]:
        try:
            regex = re.compile(pattern.encode("latin-1"), re.DOTALL)
        except re.error:
            return []
        return self._find_all_regex(regex)

    # ── Internal chunked search ─────────────────────────────────────

    def _search_regex_bytes(self, regex: re.Pattern, start: int, forward: bool) -> int:
        size = self._buffer.size()
        if size == 0:
            return -1

        if forward:
            pos = start
            while pos < size:
                chunk_len = min(CHUNK_SIZE + OVERLAP, size - pos)
                chunk = self._buffer.read(pos, chunk_len)
                m = regex.search(chunk)
                if m:
                    return pos + m.start()
                pos += CHUNK_SIZE
        else:
            # Backward: search in reverse chunks
            pos = min(start, size)
            while pos > 0:
                chunk_start = max(0, pos - CHUNK_SIZE)
                chunk = self._buffer.read(chunk_start, pos - chunk_start + OVERLAP)
                # Find last match in chunk before start offset
                last = -1
                for m in regex.finditer(chunk):
                    abs_pos = chunk_start + m.start()
                    if abs_pos < start:
                        last = abs_pos
                if last >= 0:
                    return last
                pos = chunk_start

        return -1

    def _find_all_regex(self, regex: re.Pattern) -> List[Tuple[int, int]]:
        results = []
        size = self._buffer.size()
        pos = 0
        while pos < size:
            chunk_len = min(CHUNK_SIZE + OVERLAP, size - pos)
            chunk = self._buffer.read(pos, chunk_len)
            for m in regex.finditer(chunk):
                abs_off = pos + m.start()
                length = m.end() - m.start()
                # Avoid duplicates from overlap region
                if not results or abs_off > results[-1][0]:
                    results.append((abs_off, length))
            pos += CHUNK_SIZE
        return results


class HexSearchDialog(QDialog):
    """Non-modal search dialog with Hex/Text/Regex tabs."""

    navigate_requested = Signal(int, int)  # offset, length

    def __init__(self, buffer: HexDataBuffer, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Find")
        self.setMinimumSize(500, 400)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, False)

        self._buffer = buffer
        self._engine = HexSearchEngine(buffer)
        self._last_offset = 0

        layout = QVBoxLayout(self)

        # Tabs
        self._tabs = QTabWidget()
        layout.addWidget(self._tabs)

        # Hex tab
        hex_tab = QWidget()
        hl = QVBoxLayout(hex_tab)
        self._hex_input = QLineEdit()
        self._hex_input.setPlaceholderText("e.g. 4D 5A ?? 00 03")
        self._hex_input.returnPressed.connect(self._find_next_hex)
        hl.addWidget(QLabel("Hex Pattern (use ?? for wildcards):"))
        hl.addWidget(self._hex_input)
        hl.addStretch()
        self._tabs.addTab(hex_tab, "Hex")

        # Text tab
        text_tab = QWidget()
        tl = QVBoxLayout(text_tab)
        self._text_input = QLineEdit()
        self._text_input.setPlaceholderText("Search text...")
        self._text_input.returnPressed.connect(self._find_next_text)
        tl.addWidget(QLabel("Text:"))
        tl.addWidget(self._text_input)
        opt_row = QHBoxLayout()
        self._case_cb = QCheckBox("Case sensitive")
        self._case_cb.setChecked(True)
        opt_row.addWidget(self._case_cb)
        self._enc_utf16 = QCheckBox("UTF-16LE")
        opt_row.addWidget(self._enc_utf16)
        opt_row.addStretch()
        tl.addLayout(opt_row)
        tl.addStretch()
        self._tabs.addTab(text_tab, "Text")

        # Regex tab
        regex_tab = QWidget()
        rl = QVBoxLayout(regex_tab)
        self._regex_input = QLineEdit()
        self._regex_input.setPlaceholderText(r"e.g. \x4D\x5A..\x00")
        self._regex_input.returnPressed.connect(self._find_next_regex)
        rl.addWidget(QLabel("Regex (on raw bytes, latin-1):"))
        rl.addWidget(self._regex_input)
        rl.addStretch()
        self._tabs.addTab(regex_tab, "Regex")

        # Buttons
        btn_row = QHBoxLayout()
        self._btn_prev = QPushButton("Find Previous")
        self._btn_prev.clicked.connect(self._find_prev)
        btn_row.addWidget(self._btn_prev)
        self._btn_next = QPushButton("Find Next")
        self._btn_next.setDefault(True)
        self._btn_next.clicked.connect(self._find_next)
        btn_row.addWidget(self._btn_next)
        self._btn_all = QPushButton("Find All")
        self._btn_all.clicked.connect(self._find_all)
        btn_row.addWidget(self._btn_all)
        layout.addLayout(btn_row)

        # Progress
        self._progress = QProgressBar()
        self._progress.setVisible(False)
        layout.addWidget(self._progress)

        # Results table
        self._results_table = QTableWidget()
        self._results_table.setColumnCount(3)
        self._results_table.setHorizontalHeaderLabels(["Offset", "Length", "Preview"])
        self._results_table.horizontalHeader().setStretchLastSection(True)
        self._results_table.verticalHeader().setVisible(False)
        self._results_table.verticalHeader().setDefaultSectionSize(20)
        self._results_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._results_table.cellDoubleClicked.connect(self._on_result_double_click)
        layout.addWidget(self._results_table)

    def set_buffer(self, buffer: HexDataBuffer):
        self._buffer = buffer
        self._engine = HexSearchEngine(buffer)
        self._last_offset = 0
        self._results_table.setRowCount(0)

    # ── Find next / prev dispatch ───────────────────────────────────

    def _find_next(self):
        idx = self._tabs.currentIndex()
        if idx == 0:
            self._find_next_hex()
        elif idx == 1:
            self._find_next_text()
        else:
            self._find_next_regex()

    def _find_prev(self):
        idx = self._tabs.currentIndex()
        if idx == 0:
            self._find_hex(forward=False)
        elif idx == 1:
            self._find_text(forward=False)
        else:
            self._find_regex(forward=False)

    # ── Hex ─────────────────────────────────────────────────────────

    def _find_next_hex(self):
        self._find_hex(forward=True)

    def _find_hex(self, forward=True):
        pattern = self._hex_input.text().strip()
        if not pattern:
            return
        start = self._last_offset + (1 if forward else 0)
        off = self._engine.search_hex(pattern, start, forward)
        if off >= 0:
            self._last_offset = off
            self.navigate_requested.emit(off, len(pattern.split()))
        else:
            QMessageBox.information(self, "Not Found", "Pattern not found.")

    # ── Text ────────────────────────────────────────────────────────

    def _find_next_text(self):
        self._find_text(forward=True)

    def _find_text(self, forward=True):
        text = self._text_input.text()
        if not text:
            return
        enc = "utf-16-le" if self._enc_utf16.isChecked() else "ascii"
        case = self._case_cb.isChecked()
        start = self._last_offset + (1 if forward else 0)
        off = self._engine.search_text(text, enc, case, start, forward)
        if off >= 0:
            self._last_offset = off
            blen = len(text.encode("utf-16-le" if enc == "utf-16-le" else "utf-8"))
            self.navigate_requested.emit(off, blen)
        else:
            QMessageBox.information(self, "Not Found", "Text not found.")

    # ── Regex ───────────────────────────────────────────────────────

    def _find_next_regex(self):
        self._find_regex(forward=True)

    def _find_regex(self, forward=True):
        pattern = self._regex_input.text().strip()
        if not pattern:
            return
        start = self._last_offset + (1 if forward else 0)
        off = self._engine.search_regex(pattern, start, forward)
        if off >= 0:
            self._last_offset = off
            self.navigate_requested.emit(off, 1)
        else:
            QMessageBox.information(self, "Not Found", "Pattern not found.")

    # ── Find all ────────────────────────────────────────────────────

    def _find_all(self):
        idx = self._tabs.currentIndex()
        results = []
        if idx == 0:
            pattern = self._hex_input.text().strip()
            if pattern:
                results = self._engine.find_all_hex(pattern)
        elif idx == 1:
            text = self._text_input.text()
            if text:
                enc = "utf-16-le" if self._enc_utf16.isChecked() else "ascii"
                case = self._case_cb.isChecked()
                results = self._engine.find_all_text(text, enc, case)
        else:
            pattern = self._regex_input.text().strip()
            if pattern:
                results = self._engine.find_all_regex(pattern)

        self._results_table.setRowCount(0)
        if not results:
            QMessageBox.information(self, "Find All", "No matches found.")
            return

        self._results_table.setRowCount(len(results))
        for i, (off, length) in enumerate(results):
            self._results_table.setItem(i, 0, QTableWidgetItem(f"0x{off:08X}"))
            self._results_table.setItem(i, 1, QTableWidgetItem(str(length)))
            preview = self._buffer.read(off, min(length, 16))
            hex_str = " ".join(f"{b:02X}" for b in preview)
            self._results_table.setItem(i, 2, QTableWidgetItem(hex_str))

    def _on_result_double_click(self, row, col):
        item = self._results_table.item(row, 0)
        len_item = self._results_table.item(row, 1)
        if item and len_item:
            off = int(item.text(), 16)
            length = int(len_item.text())
            self._last_offset = off
            self.navigate_requested.emit(off, length)
