import pytest
from PySide6.QtCore import QPoint, QPointF, Qt
from PySide6.QtGui import QFont, QFontInfo, QWheelEvent
from PySide6.QtTest import QTest

from hex_editor.hex_data_buffer import HexDataBuffer
from hex_editor.hex_widget import HexWidget


@pytest.fixture
def view(app):
    widget = HexWidget()
    buffer = HexDataBuffer()
    buffer.open_bytes((b'MNW' * 1000 + b'\n') * 100)
    widget.set_buffer(buffer)
    widget.setFont(QFont('DejaVu Sans Mono', 12))
    widget.resize(650, 350)
    widget.show()
    widget.activateWindow()
    widget.setFocus()
    QTest.qWait(10)
    yield widget
    widget.close()
    widget.deleteLater()
    buffer.close()


def wheel(app, view, delta, modifiers=Qt.KeyboardModifier.ControlModifier, pixels=False):
    point = QPointF(240, 120)
    event = QWheelEvent(point, view.viewport().mapToGlobal(point.toPoint()),
                        QPoint(0, delta) if pixels else QPoint(),
                        QPoint() if pixels else QPoint(0, delta),
                        Qt.MouseButton.NoButton, modifiers, Qt.ScrollPhase.NoScrollPhase, False)
    app.sendEvent(view.viewport(), event)


@pytest.mark.parametrize('mode', ['hex', 'text', 'escaped'])
def test_zoom_keys_and_wheel_preserve_data_selection_and_monospace(app, view, mode):
    view.set_text_mode(mode != 'hex')
    view.set_text_escape_mode(mode == 'escaped')
    view.read_only = False
    view.navigate_to_offset(300, 4)
    original = view._buffer.read(0, view._buffer.size())
    selection = view.selection_model.ordered_selection()
    QTest.keyClick(view, Qt.Key.Key_Equal, Qt.KeyboardModifier.ControlModifier)
    assert view.font().pointSize() == 13
    QTest.keyClick(view, Qt.Key.Key_Plus, Qt.KeyboardModifier.ControlModifier)
    assert view.font().pointSize() == 14
    QTest.keyClick(view, Qt.Key.Key_Minus, Qt.KeyboardModifier.ControlModifier)
    assert view.font().pointSize() == 13
    wheel(app, view, 60)
    assert view.font().pointSize() == 13
    wheel(app, view, 60)
    assert view.font().pointSize() == 14
    wheel(app, view, -40, pixels=True)
    assert view.font().pointSize() == 13
    QTest.keyClick(view, Qt.Key.Key_0, Qt.KeyboardModifier.ControlModifier)
    assert view.font().pointSize() == 12
    assert QFontInfo(view.font()).fixedPitch()
    assert view.selection_model.ordered_selection() == selection
    assert view._buffer.read(0, view._buffer.size()) == original


def test_zoom_limits_and_plain_wheel_scroll(app, view):
    view.zoom_font(-1000)
    assert view.font().pointSize() == 6
    view.zoom_font(1000)
    assert view.font().pointSize() == 72
    wheel(app, view, 120)
    assert view.font().pointSize() == 72
    view.reset_font_zoom()
    view.verticalScrollBar().setValue(100)
    wheel(app, view, -120, Qt.KeyboardModifier.NoModifier)
    assert view.verticalScrollBar().value() > 100
    assert view.font().pointSize() == 12


def test_zoom_does_not_use_unresolved_platform_point_size(app, view, monkeypatch):
    import hex_editor.hex_widget as module
    from types import SimpleNamespace

    real_info = module.QFontInfo
    monkeypatch.setattr(module, 'QFontInfo', lambda font: SimpleNamespace(
        fixedPitch=real_info(font).fixedPitch, pointSizeF=lambda: -1))
    view.setFont(QFont(view.font().family(), 12))
    view.zoom_font(1)
    assert view.font().pointSize() == 13
    view.zoom_font(1)
    assert view.font().pointSize() == 14
    view.reset_font_zoom()
    assert view.font().pointSize() == 12


def test_pixel_font_zoom_and_reset_preserve_configured_size(app, view):
    font = view.font()
    font.setPixelSize(24)
    view.setFont(font)
    base = 24 * 72.0 / view.logicalDpiY()
    view.zoom_font(1)
    assert view.font().pointSizeF() == pytest.approx(base + 1, abs=.01)
    view.reset_font_zoom()
    assert view.font().pointSizeF() == pytest.approx(base, abs=.01)


def test_shifted_and_keypad_plus_also_zoom_an_empty_view(app):
    widget = HexWidget()
    widget.show()
    widget.activateWindow()
    widget.setFocus()
    QTest.qWait(10)
    try:
        initial = widget.font().pointSize()
        for step, extra in enumerate((Qt.KeyboardModifier.ShiftModifier,
                                      Qt.KeyboardModifier.KeypadModifier), 1):
            QTest.keyClick(widget, Qt.Key.Key_Plus, Qt.KeyboardModifier.ControlModifier | extra)
            assert widget.font().pointSize() == initial + step
    finally:
        widget.close()
        widget.deleteLater()


def test_long_text_scroll_zoom_and_hit_testing_read_only_visible_slice(app, view, monkeypatch):
    view._buffer.open_bytes(b'M' * 1_000_000 + b'\nshort\n')
    view.set_buffer(view._buffer)
    view.set_text_mode(True)
    view.navigate_to_offset(950_000)
    assert view.horizontalScrollBar().value() > 0
    reads = []
    read = view._buffer.read
    def recorded(offset, length):
        reads.append(length)
        return read(offset, length)
    monkeypatch.setattr(view._buffer, 'read', recorded)
    def unexpected_reindex():
        raise AssertionError('Zoom rebuilt the text index')
    monkeypatch.setattr(view, '_rebuild_text_line_starts', unexpected_reindex)
    view.zoom_font(-2)
    view.viewport().grab()
    assert max(reads) < 200
    layout = view.layout_info
    x = 300
    expected = (x + view.horizontalScrollBar().value() - layout.offset_width - layout.char_w) // layout.char_w
    QTest.mouseClick(view.viewport(), Qt.MouseButton.LeftButton, pos=QPoint(x, layout.line_h // 2))
    assert view.selection_model.cursor == expected
