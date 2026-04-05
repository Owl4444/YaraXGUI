# -*- coding: utf-8 -*-
"""String extraction engine and results widget."""

from dataclasses import dataclass
from typing import List, Callable, Optional

from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QSpinBox, QCheckBox, QPushButton, QProgressBar,
                               QTableWidget, QTableWidgetItem, QHeaderView,
                               QAbstractItemView)

from .hex_data_buffer import HexDataBuffer

CHUNK_SIZE = 64 * 1024
OVERLAP = 256


@dataclass
class StringResult:
    offset: int
    length: int
    encoding: str  # "ASCII" or "UTF-16LE"
    value: str


class StringExtractor:
    """Extract printable ASCII and UTF-16LE strings from binary data."""

    def __init__(self, buffer: HexDataBuffer, min_length: int = 4):
        self._buffer = buffer
        self.min_length = min_length

    def extract(self, ascii_: bool = True, unicode_: bool = True,
                progress_cb: Optional[Callable[[int], None]] = None) -> List[StringResult]:
        results = []
        size = self._buffer.size()
        if size == 0:
            return results

        if ascii_:
            results.extend(self._extract_ascii(progress_cb))
        if unicode_:
            results.extend(self._extract_utf16le(progress_cb))

        results.sort(key=lambda r: r.offset)
        return results

    def _extract_ascii(self, progress_cb) -> List[StringResult]:
        results = []
        size = self._buffer.size()
        current_str = bytearray()
        current_start = 0
        pos = 0

        while pos < size:
            chunk_len = min(CHUNK_SIZE, size - pos)
            chunk = self._buffer.read(pos, chunk_len)

            for i, b in enumerate(chunk):
                if 32 <= b <= 126:
                    if not current_str:
                        current_start = pos + i
                    current_str.append(b)
                else:
                    if len(current_str) >= self.min_length:
                        results.append(StringResult(
                            offset=current_start,
                            length=len(current_str),
                            encoding="ASCII",
                            value=current_str.decode("ascii", errors="replace")
                        ))
                    current_str.clear()

            pos += chunk_len
            if progress_cb:
                progress_cb(int(pos * 50 / size))  # ASCII = first 50%

        # Flush remaining
        if len(current_str) >= self.min_length:
            results.append(StringResult(
                offset=current_start,
                length=len(current_str),
                encoding="ASCII",
                value=current_str.decode("ascii", errors="replace")
            ))

        return results

    def _extract_utf16le(self, progress_cb) -> List[StringResult]:
        results = []
        size = self._buffer.size()
        current_chars = []
        current_start = 0
        pos = 0

        while pos < size - 1:
            chunk_len = min(CHUNK_SIZE, size - pos)
            # Ensure even chunk
            if chunk_len % 2 != 0:
                chunk_len -= 1
            if chunk_len <= 0:
                break
            chunk = self._buffer.read(pos, chunk_len)

            for i in range(0, len(chunk) - 1, 2):
                lo = chunk[i]
                hi = chunk[i + 1]
                code = lo | (hi << 8)
                if 32 <= code <= 126 or code == 0x0A or code == 0x0D:
                    if not current_chars:
                        current_start = pos + i
                    current_chars.append(chr(code))
                else:
                    if len(current_chars) >= self.min_length:
                        val = "".join(current_chars)
                        results.append(StringResult(
                            offset=current_start,
                            length=len(current_chars) * 2,
                            encoding="UTF-16LE",
                            value=val
                        ))
                    current_chars.clear()

            pos += chunk_len
            if progress_cb:
                progress_cb(50 + int(pos * 50 / size))

        if len(current_chars) >= self.min_length:
            val = "".join(current_chars)
            results.append(StringResult(
                offset=current_start,
                length=len(current_chars) * 2,
                encoding="UTF-16LE",
                value=val
            ))

        return results


class _ExtractThread(QThread):
    """Worker thread for string extraction."""
    progress = Signal(int)
    finished_results = Signal(list)

    def __init__(self, extractor: StringExtractor, ascii_: bool, unicode_: bool):
        super().__init__()
        self._extractor = extractor
        self._ascii = ascii_
        self._unicode = unicode_

    def run(self):
        results = self._extractor.extract(
            self._ascii, self._unicode,
            progress_cb=lambda v: self.progress.emit(v)
        )
        self.finished_results.emit(results)


class StringResultsWidget(QWidget):
    """Widget for string extraction settings and results display."""

    navigate_requested = Signal(int, int)  # offset, length

    def __init__(self, parent=None):
        super().__init__(parent)
        self._buffer: HexDataBuffer | None = None
        self._results: List[StringResult] = []
        self._thread: Optional[_ExtractThread] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Settings row
        settings = QHBoxLayout()
        settings.addWidget(QLabel("Min length:"))
        self._min_spin = QSpinBox()
        self._min_spin.setRange(2, 256)
        self._min_spin.setValue(4)
        settings.addWidget(self._min_spin)

        self._ascii_cb = QCheckBox("ASCII")
        self._ascii_cb.setChecked(True)
        settings.addWidget(self._ascii_cb)

        self._unicode_cb = QCheckBox("Unicode")
        self._unicode_cb.setChecked(True)
        settings.addWidget(self._unicode_cb)

        self._extract_btn = QPushButton("Extract")
        self._extract_btn.clicked.connect(self._on_extract)
        settings.addWidget(self._extract_btn)

        settings.addStretch()

        # Filter
        from search_filter import DebouncedSearchBar
        self._filter_bar = DebouncedSearchBar("Filter strings...", self)
        settings.addWidget(self._filter_bar)
        self._filter_bar.debounced_text_changed.connect(self._apply_filter)

        layout.addLayout(settings)

        # Progress
        self._progress = QProgressBar()
        self._progress.setVisible(False)
        self._progress.setFixedHeight(16)
        layout.addWidget(self._progress)

        # Results table
        self._table = QTableWidget()
        self._table.setColumnCount(4)
        self._table.setHorizontalHeaderLabels(["Offset", "Length", "Encoding", "String"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.verticalHeader().setVisible(False)
        self._table.verticalHeader().setDefaultSectionSize(20)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.cellDoubleClicked.connect(self._on_double_click)
        layout.addWidget(self._table)

        # Status
        self._status = QLabel("")
        layout.addWidget(self._status)

    def set_buffer(self, buf: HexDataBuffer):
        self._buffer = buf
        self._results.clear()
        self._table.setRowCount(0)
        self._status.setText("")

    def _on_extract(self):
        if not self._buffer or self._buffer.size() == 0:
            return
        if self._thread and self._thread.isRunning():
            return

        self._extract_btn.setEnabled(False)
        self._progress.setVisible(True)
        self._progress.setValue(0)
        self._table.setRowCount(0)

        extractor = StringExtractor(self._buffer, self._min_spin.value())
        self._thread = _ExtractThread(
            extractor, self._ascii_cb.isChecked(), self._unicode_cb.isChecked()
        )
        self._thread.progress.connect(self._progress.setValue)
        self._thread.finished_results.connect(self._on_results)
        self._thread.start()

    def _on_results(self, results: List[StringResult]):
        self._results = results
        self._populate_table(results)
        self._progress.setVisible(False)
        self._extract_btn.setEnabled(True)
        self._status.setText(f"{len(results):,} strings found")
        self._thread = None

    def _populate_table(self, results: List[StringResult]):
        self._table.setRowCount(len(results))
        for i, r in enumerate(results):
            self._table.setItem(i, 0, QTableWidgetItem(f"0x{r.offset:08X}"))
            self._table.setItem(i, 1, QTableWidgetItem(str(r.length)))
            self._table.setItem(i, 2, QTableWidgetItem(r.encoding))
            # Truncate display for very long strings
            display = r.value if len(r.value) <= 200 else r.value[:200] + "..."
            self._table.setItem(i, 3, QTableWidgetItem(display))

    def _on_double_click(self, row, col):
        item = self._table.item(row, 0)
        len_item = self._table.item(row, 1)
        if item and len_item:
            off = int(item.text(), 16)
            length = int(len_item.text())
            self.navigate_requested.emit(off, length)

    def _apply_filter(self, text: str):
        text = text.lower()
        for row in range(self._table.rowCount()):
            if not text:
                self._table.setRowHidden(row, False)
                continue
            visible = False
            for col in range(self._table.columnCount()):
                item = self._table.item(row, col)
                if item and text in item.text().lower():
                    visible = True
                    break
            self._table.setRowHidden(row, not visible)
