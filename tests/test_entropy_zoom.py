import pytest
from PySide6.QtCore import QEvent, QPoint, QPointF, Qt
from PySide6.QtGui import QMouseEvent, QWheelEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from hex_editor.entropy_widget import EntropyGraphWidget, EntropyWidget


@pytest.fixture
def graph(app):
    widget = EntropyGraphWidget()
    widget.resize(800, 250)
    widget.set_data([(offset, (offset // 256) % 9) for offset in range(0, 65536, 256)], 256, 65536)
    widget.show()
    yield widget
    widget.close()
    widget.deleteLater()


def test_zoom_anchor_bounds_and_fit(graph):
    anchor = graph._graph_rect().left() + graph._graph_rect().width() // 4
    offset = graph._offset_at(anchor)
    graph.zoom(4, anchor)
    assert graph._view_size == 16384
    assert abs(graph._offset_at(anchor) - offset) <= 1
    graph.zoom(1e10)
    assert graph._view_size == 256
    graph._set_view(1e20, 256)
    assert graph._view_start == 65536 - 256
    graph._set_view(-100, 256)
    assert graph._view_start == 0
    graph.fit_file()
    assert (graph._view_start, graph._view_size) == (0, 65536)


def test_wheel_zoom_click_coordinates_and_drag_pan(graph):
    point = graph._graph_rect().center()
    wheel = QWheelEvent(QPointF(point), QPointF(graph.mapToGlobal(point)),
                        QPoint(), QPoint(0, 120), Qt.MouseButton.NoButton,
                        Qt.KeyboardModifier.NoModifier, Qt.ScrollPhase.NoScrollPhase, False)
    QApplication.sendEvent(graph, wheel)
    assert graph._view_size < 65536
    navigations = []
    graph.navigate_requested.connect(lambda offset, length: navigations.append(offset))
    expected = graph._offset_at(point.x())
    QTest.mouseClick(graph, Qt.MouseButton.LeftButton, pos=point)
    assert navigations == [expected]
    previous = graph._view_start
    QTest.mousePress(graph, Qt.MouseButton.LeftButton, pos=point)
    QTest.mouseMove(graph, point + QPoint(80, 0))
    QTest.mouseRelease(graph, Qt.MouseButton.LeftButton, pos=point + QPoint(80, 0))
    assert graph._view_start < previous
    assert navigations == [expected]  # dragging never jumps the hex cursor
    QTest.mouseClick(graph, Qt.MouseButton.LeftButton, pos=QPoint(point.x(), 0))
    assert navigations == [expected]  # ignore labels/margins


def test_zoomed_tooltip_and_bars_keep_real_offsets(graph):
    graph.set_sections([('middle', 16384, 16384)])
    graph._section_entropy[('middle', 16384)] = 7.2
    graph._set_view(16384, 16384)
    point = graph._graph_rect().center()
    event = QMouseEvent(QEvent.Type.MouseMove, QPointF(point), QPointF(graph.mapToGlobal(point)),
                        Qt.MouseButton.NoButton, Qt.MouseButton.NoButton, Qt.KeyboardModifier.NoModifier)
    QApplication.sendEvent(graph, event)
    assert 'math.entropy(16384, 16384)' in graph.toolTip()
    bars = graph._visible_bars(400)
    assert len(bars) == 64
    assert bars[0][0] == 0 and bars[-1][1] == 400


def test_overview_preserves_peaks_and_caches(graph):
    graph.set_data([(0, 8.0)] + [(offset, 0.0) for offset in range(1, 10000)], 1, 10000)
    bars = graph._visible_bars(100)
    assert bars[0][2] == 8.0
    assert graph._visible_bars(100) is bars
    graph.set_data([(0, 1.0)], 256, 17)
    assert graph._visible_bars(100)[0] == (0, 100, 1.0)
    graph.zoom(2)
    assert graph._view_size == 17


def test_scrollbar_handles_large_offsets_and_clear(app):
    widget = EntropyWidget()
    graph = widget._graph
    size = 8 * 1024**3
    graph.set_data([(0, 1.0), (size - 256, 7.0)], 256, size)
    graph.zoom(4)
    widget._scroll.setValue(widget._scroll.maximum())
    assert graph._view_start == size - graph._view_size
    offsets = []
    graph.navigate_requested.connect(lambda offset, length: offsets.append(offset))
    graph.navigate_requested.emit(graph._view_start, 0)
    assert offsets == [6 * 1024**3]
    graph.clear()
    assert not widget._zoom_in.isEnabled()
    assert widget._scroll.isHidden()
    widget.deleteLater()
