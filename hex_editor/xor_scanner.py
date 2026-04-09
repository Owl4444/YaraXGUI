# -*- coding: utf-8 -*-
"""XOR string scanner — brute-force single-byte XOR with results table."""

from dataclasses import dataclass
from typing import List, Optional

from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QSpinBox, QPushButton, QProgressBar,
                               QTableWidget, QTableWidgetItem, QHeaderView,
                               QAbstractItemView)

from .hex_data_buffer import HexDataBuffer

CHUNK_SIZE = 64 * 1024


@dataclass
class XorResult:
    offset: int
    length: int
    key: int
    value: str


class _XorScanThread(QThread):
    """Worker thread for brute-force single-byte XOR scan."""
    progress = Signal(int)
    finished_results = Signal(list)

    def __init__(self, buffer: HexDataBuffer, min_length: int,
                 key_start: int, key_end: int):
        super().__init__()
        self._buffer = buffer
        self._min_length = min_length
        self._key_start = key_start
        self._key_end = key_end
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        results: List[XorResult] = []
        size = self._buffer.size()
        if size == 0:
            self.finished_results.emit(results)
            return

        total_keys = self._key_end - self._key_start + 1

        for key_idx, key in enumerate(range(self._key_start, self._key_end + 1)):
            if self._cancelled:
                break

            current_run = bytearray()
            current_start = 0
            pos = 0

            while pos < size:
                if self._cancelled:
                    break
                chunk_len = min(CHUNK_SIZE, size - pos)
                chunk = self._buffer.read(pos, chunk_len)

                for i, b in enumerate(chunk):
                    decoded = b ^ key
                    if 32 <= decoded <= 126:
                        if not current_run:
                            current_start = pos + i
                        current_run.append(decoded)
                    else:
                        if len(current_run) >= self._min_length:
                            results.append(XorResult(
                                offset=current_start,
                                length=len(current_run),
                                key=key,
                                value=current_run.decode("ascii", errors="replace")
                            ))
                        current_run.clear()

                pos += chunk_len

            # Flush remaining run for this key
            if len(current_run) >= self._min_length:
                results.append(XorResult(
                    offset=current_start,
                    length=len(current_run),
                    key=key,
                    value=current_run.decode("ascii", errors="replace")
                ))

            self.progress.emit(int((key_idx + 1) * 100 / total_keys))

        results.sort(key=lambda r: r.offset)
        self.finished_results.emit(results)


class XorScannerWidget(QWidget):
    """Widget for XOR string scanning with controls and results table."""

    navigate_requested = Signal(int, int)  # offset, length

    def __init__(self, parent=None):
        super().__init__(parent)
        self._buffer: HexDataBuffer | None = None
        self._results: List[XorResult] = []
        self._thread: Optional[_XorScanThread] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Settings row
        settings = QHBoxLayout()
        settings.addWidget(QLabel("Min length:"))
        self._min_spin = QSpinBox()
        self._min_spin.setRange(2, 256)
        self._min_spin.setValue(4)
        settings.addWidget(self._min_spin)

        settings.addWidget(QLabel("Key range:"))
        self._key_start_spin = QSpinBox()
        self._key_start_spin.setRange(0x00, 0xFF)
        self._key_start_spin.setValue(0x01)
        self._key_start_spin.setPrefix("0x")
        self._key_start_spin.setDisplayIntegerBase(16)
        settings.addWidget(self._key_start_spin)

        settings.addWidget(QLabel("-"))
        self._key_end_spin = QSpinBox()
        self._key_end_spin.setRange(0x00, 0xFF)
        self._key_end_spin.setValue(0xFF)
        self._key_end_spin.setPrefix("0x")
        self._key_end_spin.setDisplayIntegerBase(16)
        settings.addWidget(self._key_end_spin)

        self._scan_btn = QPushButton("Scan")
        self._scan_btn.clicked.connect(self._on_scan)
        settings.addWidget(self._scan_btn)

        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.clicked.connect(self._on_cancel)
        settings.addWidget(self._cancel_btn)

        settings.addStretch()

        # Filter
        from search_filter import DebouncedSearchBar
        self._filter_bar = DebouncedSearchBar("Filter results...", self)
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
        self._table.setHorizontalHeaderLabels(["Offset", "Length", "XOR Key", "Decoded String"])
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

    def _on_scan(self):
        if not self._buffer or self._buffer.size() == 0:
            return
        if self._thread and self._thread.isRunning():
            return

        self._scan_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self._progress.setVisible(True)
        self._progress.setValue(0)
        self._table.setRowCount(0)

        self._thread = _XorScanThread(
            self._buffer,
            self._min_spin.value(),
            self._key_start_spin.value(),
            self._key_end_spin.value()
        )
        self._thread.progress.connect(self._progress.setValue)
        self._thread.finished_results.connect(self._on_results)
        self._thread.start()

    def _on_cancel(self):
        if self._thread and self._thread.isRunning():
            self._thread.cancel()

    def _on_results(self, results: List[XorResult]):
        self._results = results
        self._populate_table(results)
        self._progress.setVisible(False)
        self._scan_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
        self._status.setText(f"{len(results):,} XOR strings found")
        self._thread = None

    def _populate_table(self, results: List[XorResult]):
        self._table.setRowCount(len(results))
        for i, r in enumerate(results):
            self._table.setItem(i, 0, QTableWidgetItem(f"0x{r.offset:08X}"))
            self._table.setItem(i, 1, QTableWidgetItem(str(r.length)))
            self._table.setItem(i, 2, QTableWidgetItem(f"0x{r.key:02X}"))
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
