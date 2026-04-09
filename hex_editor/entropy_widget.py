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


def _fmt_offset(offset: int) -> str:
    """Short hex offset for axis labels ('0', '0x1.2K', '0x4.0M', ...)."""
    if offset <= 0:
        return "0"
    if offset < 1024:
        return f"0x{offset:X}"
    if offset < 1024 * 1024:
        return f"{offset / 1024:.1f}K"
    if offset < 1024 * 1024 * 1024:
        return f"{offset / (1024 * 1024):.1f}M"
    return f"{offset / (1024 * 1024 * 1024):.1f}G"


def _classify_entropy(value: float) -> str:
    """One-letter classification (low / medium / high / very-high)."""
    if value < 3.0:
        return "text"
    if value < 5.5:
        return "code"
    if value < 6.8:
        return "data"
    if value < 7.5:
        return "packed"
    return "encrypted"


class EntropyGraphWidget(QWidget):
    """Custom-painted entropy graph with section overlays and cursor line.

    The graph always spans the full file (offset 0 -> file_size).
    Sections are drawn as translucent background bands with per-section
    average-entropy labels. Regions not covered by any section become
    pseudo-sections named ``Header`` (leading gap) or ``Overlay``
    (trailing gap), so the whole file is accounted for.
    """

    navigate_requested = Signal(int, int)  # offset, length=0

    # Drawing constants
    _MARGIN_LEFT = 44
    _MARGIN_RIGHT = 12
    _MARGIN_TOP = 12
    _MARGIN_BOTTOM = 34  # larger to hold the X-axis offset labels

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data: List[Tuple[int, float]] = []  # (offset, entropy)
        self._block_size = 256
        self._file_size = 0
        self._cursor_offset = -1
        self._sections: List[Tuple[str, int, int]] = []  # (name, raw_offset, raw_size)
        self._effective_sections: List[Tuple[str, int, int]] = []  # filled-in version
        self._section_avg: dict[Tuple[str, int], float] = {}
        self.setMinimumHeight(140)
        self.setMouseTracking(True)

    def set_data(self, data: List[Tuple[int, float]], block_size: int, file_size: int):
        self._data = data
        self._block_size = block_size
        self._file_size = file_size
        self._rebuild_effective_sections()
        self._recompute_section_stats()
        self.update()

    def set_sections(self, sections: List[Tuple[str, int, int]]):
        self._sections = list(sections)
        self._rebuild_effective_sections()
        self._recompute_section_stats()
        self.update()

    def set_cursor_offset(self, offset: int):
        self._cursor_offset = offset
        self.update()

    def clear(self):
        self._data.clear()
        self._sections.clear()
        self._effective_sections.clear()
        self._section_avg.clear()
        self._cursor_offset = -1
        self.update()

    # ── section bookkeeping ────────────────────────────────────────
    def _rebuild_effective_sections(self):
        """Fill gaps around the real sections with ``Header`` / ``Gap``
        / ``Overlay`` pseudo-entries so the whole file is labeled."""
        self._effective_sections = []
        if self._file_size <= 0:
            return

        # Clamp, drop zero-size, sort by start offset.
        clean: List[Tuple[str, int, int]] = []
        for name, off, size in self._sections:
            if size <= 0:
                continue
            start = max(0, int(off))
            end = min(self._file_size, int(off + size))
            if end <= start:
                continue
            clean.append((name, start, end - start))
        clean.sort(key=lambda t: t[1])

        if not clean:
            # No section metadata — one big "File" band.
            self._effective_sections.append(("File", 0, self._file_size))
            return

        cursor = 0
        for name, start, size in clean:
            if start > cursor:
                gap_name = "Header" if cursor == 0 else "Gap"
                self._effective_sections.append(
                    (gap_name, cursor, start - cursor))
            self._effective_sections.append((name, start, size))
            cursor = start + size
        if cursor < self._file_size:
            self._effective_sections.append(
                ("Overlay", cursor, self._file_size - cursor))

    def _recompute_section_stats(self):
        """Per-section average entropy, keyed by ``(name, start)``."""
        self._section_avg = {}
        if not self._data:
            return
        for name, start, size in self._effective_sections:
            end = start + size
            vals: List[float] = []
            for off, entropy in self._data:
                block_end = off + self._block_size
                # include blocks that overlap the section range
                if block_end <= start:
                    continue
                if off >= end:
                    break  # data is sorted by offset
                vals.append(entropy)
            if vals:
                self._section_avg[(name, start)] = sum(vals) / len(vals)

    # ── painting ───────────────────────────────────────────────────
    def _graph_rect(self) -> QRect:
        return QRect(
            self._MARGIN_LEFT, self._MARGIN_TOP,
            max(0, self.width() - self._MARGIN_LEFT - self._MARGIN_RIGHT),
            max(0, self.height() - self._MARGIN_TOP - self._MARGIN_BOTTOM),
        )

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

        rect = self._graph_rect()
        graph_w = rect.width()
        graph_h = rect.height()
        if graph_w <= 0 or graph_h <= 0:
            painter.end()
            return

        margin_left = rect.left()
        margin_top = rect.top()

        def x_for_offset(offset: int) -> int:
            if self._file_size <= 0:
                return margin_left
            return margin_left + int(offset * graph_w / self._file_size)

        # Y-axis grid and labels
        painter.setPen(QColor("#666666"))
        for level in range(0, 9, 2):
            y = margin_top + int(graph_h * (1 - level / 8.0))
            painter.drawText(0, y - 6, margin_left - 4, 12,
                             Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                             str(level))
            painter.setPen(QPen(QColor(60, 60, 60), 1, Qt.PenStyle.DotLine))
            painter.drawLine(margin_left, y, margin_left + graph_w, y)
            painter.setPen(QColor("#666666"))

        # Section background bands — drawn BEFORE the bars so the
        # entropy bars paint on top with full colour.
        band_colors = [QColor(80, 100, 140, 60), QColor(140, 100, 80, 60)]
        for i, (name, start, size) in enumerate(self._effective_sections):
            x0 = x_for_offset(start)
            x1 = x_for_offset(min(self._file_size, start + size))
            if x1 <= x0:
                continue
            painter.fillRect(x0, margin_top, x1 - x0, graph_h,
                             band_colors[i % 2])

        # Entropy bars (stretched evenly across the graph width)
        n = len(self._data)
        if n > 0:
            for i, (offset, entropy) in enumerate(self._data):
                x = margin_left + int(i * graph_w / n)
                x_next = margin_left + int((i + 1) * graph_w / n)
                bar_w = max(1, x_next - x)
                bar_h = int(graph_h * entropy / 8.0)
                y = margin_top + graph_h - bar_h
                painter.fillRect(x, y, bar_w, bar_h, _entropy_color(entropy))

        # Section boundaries + labels (drawn ON TOP of the bars)
        for name, start, size in self._effective_sections:
            x0 = x_for_offset(start)
            x1 = x_for_offset(min(self._file_size, start + size))
            band_w = x1 - x0
            if band_w <= 0:
                continue

            # dashed boundary on the left edge of the section
            if start > 0:
                painter.setPen(QPen(QColor(220, 220, 220, 140), 1,
                                    Qt.PenStyle.DashLine))
                painter.drawLine(x0, margin_top, x0, margin_top + graph_h)

            # Section label: name + avg entropy (if we have it and
            # the band is wide enough to host readable text)
            avg = self._section_avg.get((name, start))
            if avg is not None:
                label = f"{name}  {avg:.2f}  ({_classify_entropy(avg)})"
            else:
                label = name

            label_pen = QColor(240, 240, 240, 220)
            painter.setPen(label_pen)
            fm = painter.fontMetrics()
            text_w = fm.horizontalAdvance(label)
            # Only draw if the label fits inside the band (avoid
            # visual clutter on tiny sections).
            if band_w >= text_w + 6:
                # tiny shadow backing for readability
                shadow = QColor(0, 0, 0, 140)
                painter.fillRect(x0 + 3, margin_top + 3,
                                 text_w + 4, fm.height() + 2, shadow)
                painter.drawText(x0 + 5,
                                 margin_top + 4 + fm.ascent(),
                                 label)

        # Cursor position line
        if 0 <= self._cursor_offset < self._file_size:
            x = x_for_offset(self._cursor_offset)
            painter.setPen(QPen(QColor(255, 255, 0, 220), 2))
            painter.drawLine(x, margin_top, x, margin_top + graph_h)

        # Border
        painter.setPen(QColor("#555555"))
        painter.drawRect(margin_left, margin_top, graph_w, graph_h)

        # X-axis offset labels — always show 0 at the left and
        # file_size at the right, plus quarter ticks.
        painter.setPen(QColor("#888888"))
        fm = painter.fontMetrics()
        axis_y = margin_top + graph_h
        ticks = [0.0, 0.25, 0.5, 0.75, 1.0]
        for i, t in enumerate(ticks):
            off = int(self._file_size * t)
            x = margin_left + int(graph_w * t)
            painter.setPen(QPen(QColor(90, 90, 90), 1))
            painter.drawLine(x, axis_y, x, axis_y + 3)
            painter.setPen(QColor("#aaaaaa"))
            label = _fmt_offset(off)
            lw = fm.horizontalAdvance(label)
            if i == 0:
                lx = x
            elif i == len(ticks) - 1:
                lx = x - lw
            else:
                lx = x - lw // 2
            painter.drawText(lx, axis_y + 4 + fm.ascent(), label)

        painter.end()

    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.MouseButton.LeftButton and self._data and self._file_size > 0:
            rect = self._graph_rect()
            x = event.position().x() - rect.left()
            if 0 <= x <= rect.width() and rect.width() > 0:
                offset = int(x * self._file_size / rect.width())
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
