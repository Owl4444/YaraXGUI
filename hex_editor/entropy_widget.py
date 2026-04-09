# -*- coding: utf-8 -*-
"""Entropy heatmap — Shannon entropy graph with section overlays."""

import math
from typing import List, Optional, Tuple

from PySide6.QtCore import Qt, Signal, QThread, QRect
from PySide6.QtGui import QColor, QPainter, QPen, QLinearGradient, QMouseEvent
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QSpinBox, QPushButton, QProgressBar)

from .hex_data_buffer import HexDataBuffer


def _calculate_entropy(data: bytes) -> float:
    """Shannon entropy of *data*, 0.0 (uniform) to 8.0 (random)."""
    length = len(data)
    if length == 0:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _entropy_color(value: float) -> QColor:
    """Map entropy 0-8 to blue → green → yellow → red."""
    t = max(0.0, min(value / 8.0, 1.0))
    if t < 0.333:
        # blue → green
        r = t / 0.333
        return QColor(0, int(200 * r), int(255 * (1 - r)))
    elif t < 0.667:
        # green → yellow
        r = (t - 0.333) / 0.334
        return QColor(int(255 * r), 200, 0)
    else:
        # yellow → red
        r = (t - 0.667) / 0.333
        return QColor(255, int(200 * (1 - r)), 0)


class _EntropyCalcThread(QThread):
    """Background Shannon entropy calculation per block."""
    progress = Signal(int)
    finished_results = Signal(list)  # list of (offset, entropy_value)

    def __init__(self, buffer: HexDataBuffer, block_size: int):
        super().__init__()
        self._buffer = buffer
        self._block_size = block_size
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        results: List[Tuple[int, float]] = []
        size = self._buffer.size()
        if size == 0:
            self.finished_results.emit(results)
            return

        block_size = self._block_size
        total_blocks = (size + block_size - 1) // block_size
        offset = 0
        count = 0

        while offset < size:
            if self._cancelled:
                break
            chunk = self._buffer.read(offset, min(block_size, size - offset))
            entropy = _calculate_entropy(chunk)
            results.append((offset, entropy))
            offset += block_size
            count += 1
            if count % 100 == 0:
                self.progress.emit(int(count * 100 / total_blocks))

        self.progress.emit(100)
        self.finished_results.emit(results)


class EntropyGraphWidget(QWidget):
    """Custom-painted entropy graph with section overlays and cursor line."""

    navigate_requested = Signal(int, int)  # offset, length=0

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data: List[Tuple[int, float]] = []  # (offset, entropy)
        self._block_size = 256
        self._file_size = 0
        self._cursor_offset = -1
        self._sections: List[Tuple[str, int, int]] = []  # (name, raw_offset, raw_size)
        self.setMinimumHeight(100)
        self.setMouseTracking(True)

    def set_data(self, data: List[Tuple[int, float]], block_size: int, file_size: int):
        self._data = data
        self._block_size = block_size
        self._file_size = file_size
        self.update()

    def set_sections(self, sections: List[Tuple[str, int, int]]):
        self._sections = sections
        self.update()

    def set_cursor_offset(self, offset: int):
        self._cursor_offset = offset
        self.update()

    def clear(self):
        self._data.clear()
        self._sections.clear()
        self._cursor_offset = -1
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w = self.width()
        h = self.height()
        painter.fillRect(0, 0, w, h, QColor("#1e1e1e"))

        if not self._data or self._file_size == 0:
            painter.setPen(QColor("#888888"))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                             "Click Calculate to generate entropy graph")
            painter.end()
            return

        margin_left = 35
        margin_right = 10
        margin_top = 10
        margin_bottom = 20
        graph_w = w - margin_left - margin_right
        graph_h = h - margin_top - margin_bottom

        if graph_w <= 0 or graph_h <= 0:
            painter.end()
            return

        # Y-axis labels and grid
        painter.setPen(QColor("#666666"))
        for level in range(0, 9, 2):
            y = margin_top + int(graph_h * (1 - level / 8.0))
            painter.drawText(0, y - 6, margin_left - 4, 12,
                             Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                             str(level))
            painter.setPen(QPen(QColor(60, 60, 60), 1, Qt.PenStyle.DotLine))
            painter.drawLine(margin_left, y, w - margin_right, y)
            painter.setPen(QColor("#666666"))

        # Draw entropy bars
        n = len(self._data)
        bar_w = max(1, graph_w / n)
        for i, (offset, entropy) in enumerate(self._data):
            x = margin_left + int(i * graph_w / n)
            bar_h = int(graph_h * entropy / 8.0)
            y = margin_top + graph_h - bar_h
            color = _entropy_color(entropy)
            painter.fillRect(int(x), y, max(1, int(bar_w) + 1), bar_h, color)

        # Section boundaries (dashed vertical lines with labels)
        for name, sec_offset, sec_size in self._sections:
            if sec_offset > 0 and sec_offset < self._file_size:
                x = margin_left + int(sec_offset * graph_w / self._file_size)
                painter.setPen(QPen(QColor(200, 200, 200, 120), 1, Qt.PenStyle.DashLine))
                painter.drawLine(x, margin_top, x, margin_top + graph_h)
                painter.setPen(QColor(200, 200, 200, 180))
                painter.drawText(x + 2, margin_top + 12, name)

        # Cursor position line
        if 0 <= self._cursor_offset < self._file_size:
            x = margin_left + int(self._cursor_offset * graph_w / self._file_size)
            painter.setPen(QPen(QColor(255, 255, 0, 200), 2))
            painter.drawLine(x, margin_top, x, margin_top + graph_h)

        # Border
        painter.setPen(QColor("#555555"))
        painter.drawRect(margin_left, margin_top, graph_w, graph_h)

        painter.end()

    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.MouseButton.LeftButton and self._data and self._file_size > 0:
            margin_left = 35
            margin_right = 10
            graph_w = self.width() - margin_left - margin_right
            x = event.position().x() - margin_left
            if 0 <= x <= graph_w:
                offset = int(x * self._file_size / graph_w)
                offset = max(0, min(offset, self._file_size - 1))
                self.navigate_requested.emit(offset, 0)
        super().mousePressEvent(event)


class EntropyWidget(QWidget):
    """Dock content widget with controls + entropy graph."""

    navigate_requested = Signal(int, int)  # offset, length

    def __init__(self, parent=None):
        super().__init__(parent)
        self._buffer: HexDataBuffer | None = None
        self._thread: Optional[_EntropyCalcThread] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Controls row
        controls = QHBoxLayout()
        controls.addWidget(QLabel("Block size:"))
        self._block_spin = QSpinBox()
        self._block_spin.setRange(64, 8192)
        self._block_spin.setValue(256)
        self._block_spin.setSingleStep(64)
        controls.addWidget(self._block_spin)

        self._calc_btn = QPushButton("Calculate")
        self._calc_btn.clicked.connect(self._on_calculate)
        controls.addWidget(self._calc_btn)

        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.clicked.connect(self._on_cancel)
        controls.addWidget(self._cancel_btn)

        controls.addStretch()

        self._avg_label = QLabel("")
        controls.addWidget(self._avg_label)
        layout.addLayout(controls)

        # Progress
        self._progress = QProgressBar()
        self._progress.setVisible(False)
        self._progress.setFixedHeight(16)
        layout.addWidget(self._progress)

        # Graph
        self._graph = EntropyGraphWidget(self)
        self._graph.navigate_requested.connect(self.navigate_requested.emit)
        layout.addWidget(self._graph, 1)

    def set_buffer(self, buf: HexDataBuffer):
        self._buffer = buf
        self._graph.clear()
        self._avg_label.setText("")
        self._load_sections()

    def set_cursor_offset(self, offset: int):
        self._graph.set_cursor_offset(offset)

    def _load_sections(self):
        """Load PE/ELF section info for overlays."""
        if not self._buffer:
            return
        sections = []
        try:
            from .pe_parser import PeParser
            pe = PeParser(self._buffer)
            info = pe.parse()
            if info and info.sections:
                for sec in info.sections:
                    sections.append((sec.name, sec.raw_offset, sec.raw_size))
        except Exception:
            pass

        if not sections:
            try:
                from .elf_parser import ElfParser
                elf = ElfParser(self._buffer)
                info = elf.parse()
                if info and info.sections:
                    for sec in info.sections:
                        if sec.size > 0:
                            sections.append((sec.name, sec.offset, sec.size))
            except Exception:
                pass

        self._graph.set_sections(sections)

    def _on_calculate(self):
        if not self._buffer or self._buffer.size() == 0:
            return
        if self._thread and self._thread.isRunning():
            return

        self._calc_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self._progress.setVisible(True)
        self._progress.setValue(0)

        self._thread = _EntropyCalcThread(self._buffer, self._block_spin.value())
        self._thread.progress.connect(self._progress.setValue)
        self._thread.finished_results.connect(self._on_results)
        self._thread.start()

    def _on_cancel(self):
        if self._thread and self._thread.isRunning():
            self._thread.cancel()

    def _on_results(self, results):
        self._progress.setVisible(False)
        self._calc_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)

        if results:
            avg = sum(e for _, e in results) / len(results)
            self._avg_label.setText(f"Avg entropy: {avg:.2f}")
            self._graph.set_data(results, self._block_spin.value(),
                                 self._buffer.size() if self._buffer else 0)
        self._thread = None
