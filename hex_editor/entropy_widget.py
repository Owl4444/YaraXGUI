# -*- coding: utf-8 -*-
"""Entropy heatmap — Shannon entropy graph with section overlays."""

import math
from bisect import bisect_left, bisect_right
from html import escape
from collections import Counter
from typing import List, Optional, Tuple

from PySide6.QtCore import Qt, Signal, QThread, QRect
from PySide6.QtGui import QColor, QPainter, QPen, QLinearGradient, QMouseEvent
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QSpinBox, QPushButton, QProgressBar, QScrollBar)

from .hex_data_buffer import HexDataBuffer
from .thread_lifecycle import retain_thread, stop_thread


def _entropy_from_counts(counts, length):
    if not length:
        return 0.0
    entropy = 0.0
    # Match YARA-X's byte-bin order as well as its floating-point formula.
    for byte in range(256):
        count = counts.get(byte, 0)
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


def _calculate_entropy(data: bytes) -> float:
    """Shannon byte entropy, matching YARA-X math.entropy for these bytes."""
    return _entropy_from_counts(Counter(data), len(data))


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
    """Compute block, file and exact-range section entropy off the GUI thread."""
    progress = Signal(int)
    finished_results = Signal(object)
    failed = Signal(str)

    def __init__(self, buffer: HexDataBuffer, block_size: int, sections=()):
        super().__init__()
        self._buffer = buffer
        self._block_size = max(1, block_size)
        self._sections = list(sections)
        self.revision = buffer.revision
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def _range_entropy(self, offset, length):
        counts = Counter()
        end = min(self._buffer.size(), offset + length)
        for position in range(offset, end, 65536):
            if self._cancelled:
                return None
            counts.update(self._buffer.read_revision(position, min(65536, end-position), self.revision))
        return _entropy_from_counts(counts, end-offset)

    def run(self):
        try:
            results = []
            size = self._buffer.size()
            counts = Counter()
            for offset in range(0, size, self._block_size):
                if self._cancelled:
                    return
                chunk = self._buffer.read_revision(offset, min(self._block_size, size-offset), self.revision)
                block_counts = Counter(chunk)
                counts.update(block_counts)
                results.append((offset, _entropy_from_counts(block_counts, len(chunk))))
                if len(results) % 100 == 0:
                    self.progress.emit(int(80 * (offset + len(chunk)) / max(size, 1)))
            whole = _entropy_from_counts(counts, size)
            sections = {}
            for index, (name, offset, length) in enumerate(self._sections):
                if self._cancelled:
                    return
                value = whole if offset == 0 and length == size else self._range_entropy(offset, length)
                if value is None:
                    return
                sections[(name, offset)] = value
                self.progress.emit(80 + int(20 * (index+1) / len(self._sections)))
            if self._cancelled:
                return
            if self._buffer.revision != self.revision:
                raise ValueError('File changed; calculate entropy again')
            self.progress.emit(100)
            self.finished_results.emit(dict(blocks=results, whole=whole, sections=sections,
                                            size=size, block_size=self._block_size))
        except Exception as exc:
            self.failed.emit(str(exc))


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

    The graph supports a bounded byte viewport with pointer-centered zoom and pan.
    Sections are drawn as translucent background bands with per-section
    exact-range entropy labels. Regions not covered by any section become
    pseudo-sections named ``Header`` (leading gap) or ``Overlay``
    (trailing gap), so the whole file is accounted for.
    """

    navigate_requested = Signal(object, int)  # offset, length=0

    view_changed = Signal(object, object)  # first byte, visible byte count

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
        self._view_start = 0
        self._view_size = 0
        self._drag_origin = None
        self._dragged = False
        self._bar_cache = None
        self._sections: List[Tuple[str, int, int]] = []  # (name, raw_offset, raw_size)
        self._effective_sections: List[Tuple[str, int, int]] = []  # filled-in version
        self._section_entropy: dict[Tuple[str, int], float] = {}
        self.setMinimumHeight(140)
        self.setMouseTracking(True)

    def set_data(self, data: List[Tuple[int, float]], block_size: int, file_size: int, section_entropy=None):
        self._data = data
        self._block_size = block_size
        self._file_size = file_size
        self._rebuild_effective_sections()
        self._section_entropy = dict(section_entropy or {})
        self._bar_cache = None
        self.fit_file()

    def set_sections(self, sections: List[Tuple[str, int, int]]):
        self._sections = list(sections)
        self._rebuild_effective_sections()
        self._section_entropy.clear()
        self.update()

    def set_cursor_offset(self, offset: int):
        self._cursor_offset = offset
        self.update()

    def clear(self):
        self._data.clear()
        self._file_size = 0
        self._sections.clear()
        self._effective_sections.clear()
        self._section_entropy.clear()
        self._cursor_offset = -1
        self._bar_cache = None
        self._drag_origin = None
        self.fit_file()

    def fit_file(self):
        self._set_view(0, self._file_size)

    def _set_view(self, start, size):
        minimum = min(self._file_size, max(1, self._block_size))
        self._view_size = min(self._file_size, max(minimum, round(size)))
        self._view_start = max(0, min(round(start), self._file_size - self._view_size))
        self.view_changed.emit(self._view_start, self._view_size)
        self.update()

    def zoom(self, factor, anchor_x=None):
        if not self._data or not self._view_size or factor <= 0 or not math.isfinite(factor):
            return
        rect = self._graph_rect()
        fraction = .5 if anchor_x is None else (anchor_x - rect.x()) / max(1, rect.width())
        fraction = max(0, min(1, fraction))
        anchor = self._view_start + self._view_size * fraction
        size = max(min(self._file_size, self._block_size), min(self._file_size, round(self._view_size / factor)))
        self._set_view(anchor - size * fraction, size)

    def _offset_at(self, x):
        rect = self._graph_rect()
        fraction = max(0, min(1, (x - rect.x()) / max(1, rect.width())))
        return max(0, min(self._file_size - 1,
                          self._view_start + int(fraction * self._view_size)))

    def _visible_bars(self, width):
        key = (self._view_start, self._view_size, width)
        if self._bar_cache is not None and self._bar_cache[0] == key:
            return self._bar_cache[1]
        start, size = self._view_start, max(1, self._view_size)
        first = max(0, bisect_right(self._data, start, key=lambda item: item[0]) - 1)
        last = bisect_left(self._data, start + size, key=lambda item: item[0])
        bars = []
        if last - first > width:
            # Keep peaks when several blocks occupy a pixel. Cache this overview
            # so cursor/hover repaints do not traverse the complete file again.
            peaks = [0.0] * width
            for index in range(first, last):
                offset, entropy = self._data[index]
                x = max(0, min(width - 1, (offset - start) * width // size))
                peaks[x] = max(peaks[x], entropy)
            bars = [(x, x + 1, value) for x, value in enumerate(peaks)]
        else:
            for index in range(first, last):
                offset, entropy = self._data[index]
                x0 = max(0, (offset - start) * width // size)
                x1 = min(width, (offset + self._block_size - start) * width // size)
                bars.append((x0, max(x0 + 1, x1), entropy))
        self._bar_cache = (key, bars)
        return bars

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
            cursor = max(cursor, start + size)
        if cursor < self._file_size:
            self._effective_sections.append(
                ("Overlay", cursor, self._file_size - cursor))

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
            return margin_left + int((offset - self._view_start) * graph_w / max(1, self._view_size))

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
        painter.save()
        painter.setClipRect(rect)
        band_colors = [QColor(80, 100, 140, 60), QColor(140, 100, 80, 60)]
        for i, (name, start, size) in enumerate(self._effective_sections):
            x0 = max(rect.left(), x_for_offset(start))
            x1 = min(rect.left() + graph_w, x_for_offset(start + size))
            if x1 <= x0:
                continue
            painter.fillRect(x0, margin_top, x1 - x0, graph_h,
                             band_colors[i % 2])

        # Render visible blocks only, preserving peaks in the overview.
        for x0, x1, entropy in self._visible_bars(graph_w):
            bar_h = int(graph_h * entropy / 8.0)
            painter.fillRect(margin_left + x0, margin_top + graph_h - bar_h,
                             x1 - x0, bar_h, _entropy_color(entropy))

        # Section boundaries + labels (drawn ON TOP of the bars)
        for name, start, size in self._effective_sections:
            x0 = max(rect.left(), x_for_offset(start))
            x1 = min(rect.left() + graph_w, x_for_offset(start + size))
            band_w = x1 - x0
            if band_w <= 0:
                continue

            # dashed boundary on the left edge of the section
            if start > 0:
                painter.setPen(QPen(QColor(220, 220, 220, 140), 1,
                                    Qt.PenStyle.DashLine))
                painter.drawLine(x0, margin_top, x0, margin_top + graph_h)

            # Section label: name + exact entropy (if we have it and
            # the band is wide enough to host readable text)
            avg = self._section_entropy.get((name, start))
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

        painter.restore()

        # Border
        painter.setPen(QColor("#555555"))
        painter.drawRect(margin_left, margin_top, graph_w, graph_h)

        # Axis labels describe the visible byte range.
        painter.setPen(QColor("#888888"))
        fm = painter.fontMetrics()
        axis_y = margin_top + graph_h
        label_width = max(fm.horizontalAdvance(_fmt_offset(self._view_start)),
                          fm.horizontalAdvance(_fmt_offset(self._view_start + self._view_size)))
        tick_count = max(2, min(5, int(graph_w / (label_width * 1.5 + 12)) + 1))
        ticks = [i / (tick_count - 1) for i in range(tick_count)]
        for i, t in enumerate(ticks):
            off = self._view_start + int(self._view_size * t)
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

    def mouseMoveEvent(self, event: QMouseEvent):
        rect = self._graph_rect()
        if self._drag_origin is not None:
            press_x, start = self._drag_origin
            distance = event.position().x() - press_x
            self._dragged |= abs(distance) >= 3
            if self._dragged:
                self.setCursor(Qt.CursorShape.ClosedHandCursor)
                self._set_view(start - distance * self._view_size / max(1, rect.width()), self._view_size)
                event.accept()
                return
        lines = []
        if self._file_size and rect.contains(event.position().toPoint()):
            offset = self._offset_at(event.position().x())
            index = max(0, bisect_right(self._data, offset, key=lambda item: item[0]) - 1)
            if self._data:
                lines.append(f'Offset 0x{offset:X} · Block entropy: {self._data[index][1]:.6f}')
            for name, start, length in self._effective_sections:
                value = self._section_entropy.get((name, start))
                if value is not None and start <= offset < start + length:
                    lines.append(f'{name}: {value:.12g} bits/byte\nmath.entropy({start}, {length})')
        self.setToolTip('<qt>' + '<br>'.join(escape(line).replace('\n', '<br>') for line in lines) + '</qt>' if lines else '')
        super().mouseMoveEvent(event)

    def mousePressEvent(self, event: QMouseEvent):
        if (event.button() == Qt.MouseButton.LeftButton and self._data
                and self._graph_rect().contains(event.position().toPoint())):
            self._drag_origin = (event.position().x(), self._view_start)
            self._dragged = False
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent):
        if event.button() == Qt.MouseButton.LeftButton and self._drag_origin is not None:
            if not self._dragged and self._graph_rect().contains(event.position().toPoint()):
                self.navigate_requested.emit(self._offset_at(event.position().x()), 0)
            self._drag_origin = None
            self.unsetCursor()
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def wheelEvent(self, event):
        if self._data and self._graph_rect().contains(event.position().toPoint()):
            steps = event.angleDelta().y() / 120 or event.pixelDelta().y() / 60
            if steps:
                self.zoom(2 ** max(-4, min(4, steps / 2)), event.position().x())
                event.accept()
                return
        event.ignore()


class EntropyWidget(QWidget):
    """Dock content widget with controls + entropy graph."""

    navigate_requested = Signal(object, int)  # offset, length

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
        self._avg_label.setToolTip("Entropy of all current bytes: math.entropy(0, filesize). The graph shows individual blocks.")
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
        self._scroll = QScrollBar(Qt.Orientation.Horizontal)
        self._scroll.valueChanged.connect(self._pan_scroll)
        layout.addWidget(self._scroll)
        zoom_row = QHBoxLayout()
        self._zoom_out = QPushButton('−')
        self._zoom_out.setToolTip('Zoom out')
        self._zoom_out.clicked.connect(lambda: self._graph.zoom(.5))
        self._zoom_in = QPushButton('+')
        self._zoom_in.setToolTip('Zoom in')
        self._zoom_in.clicked.connect(lambda: self._graph.zoom(2))
        self._fit = QPushButton('Fit File')
        self._fit.clicked.connect(self._graph.fit_file)
        for button in (self._zoom_out, self._zoom_in, self._fit):
            zoom_row.addWidget(button)
        self._range_label = QLabel()
        self._range_label.setToolTip('Wheel to zoom at the pointer; drag to pan; click to navigate.')
        zoom_row.addWidget(self._range_label, 1)
        layout.addLayout(zoom_row)
        self._graph.view_changed.connect(self._sync_zoom)
        self._sync_zoom(0, 0)

    def _sync_zoom(self, start, size):
        total = self._graph._file_size
        zoomed = 0 < size < total
        self._scroll.blockSignals(True)
        self._scroll.setRange(0, 1000000 if zoomed else 0)
        self._scroll.setPageStep(min(2000000000, max(1, int(size * 1000000 / max(1, total - size)))) if zoomed else 1)
        self._scroll.setValue(int(start * 1000000 / max(1, total - size)))
        self._scroll.blockSignals(False)
        self._scroll.setVisible(zoomed)
        self._zoom_out.setEnabled(zoomed)
        self._fit.setEnabled(zoomed)
        self._zoom_in.setEnabled(size > min(total, self._graph._block_size))
        self._range_label.setText(
            f'{total / size:.1f}× · 0x{start:X}–0x{start + size:X}' if size else '')

    def _pan_scroll(self, value):
        graph = self._graph
        graph._set_view(round((graph._file_size - graph._view_size) * value / 1000000), graph._view_size)


    def set_buffer(self, buf: HexDataBuffer):
        self.shutdown()
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
        if self._buffer is None:
            return
        if self._thread and self._thread.isRunning():
            return

        self._calc_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self._progress.setVisible(True)
        self._progress.setValue(0)

        self._graph._file_size = self._buffer.size()
        self._graph._rebuild_effective_sections()
        self._thread = _EntropyCalcThread(self._buffer, self._block_spin.value(), self._graph._effective_sections)
        self._thread.failed.connect(self._on_error)
        self._thread.progress.connect(self._progress.setValue)
        self._thread.finished_results.connect(self._on_results)
        self._thread.finished.connect(self._on_thread_finished)
        retain_thread(self._thread)
        self._thread.start()

    def _on_cancel(self):
        self.shutdown()

    def _on_results(self, results):
        if self.sender() is not self._thread or self._thread._cancelled:
            return
        self._progress.setVisible(False)
        self._calc_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)

        if self._buffer.revision != self._thread.revision:
            self._avg_label.setText('File changed; calculate again')
            return
        self._avg_label.setText(f"File entropy: {results['whole']:.6f}")
        self._graph.set_data(results['blocks'], results['block_size'], results['size'], results['sections'])
        self._thread = None

    def _on_error(self, message):
        if self.sender() is self._thread:
            self._avg_label.setText(message)

    def shutdown(self):
        stop_thread(self._thread)
        self._thread = None
        self._calc_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
        self._progress.hide()

    def _on_thread_finished(self):
        if self.sender() is not self._thread:
            return
        self._thread = None
        self._calc_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
        self._progress.hide()
