import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QFont, QFontInfo, QFontMetrics, QTextCursor
from PySide6.QtTest import QTest
from hex_editor.hex_widget import HexWidget
from hex_editor.hex_data_buffer import HexDataBuffer
from yaraxgui.editor.widget import YaraTextEdit


@pytest.mark.parametrize('size', [10, 24, 48])
def test_hex_font_cells_scroll_and_hit_testing(app, size):
    view = HexWidget()
    buffer = HexDataBuffer()
    buffer.open_bytes(b'MNWIMNWI' * 256)
    view.set_buffer(buffer)
    view.resize(550, 340)
    view.show()
    view.setFont(QFont('Arial', size))  # The UI font must not squeeze the byte grid.
    QTest.qWait(10)
    fm = QFontMetrics(view._font, view.viewport())
    assert QFontInfo(view._font).fixedPitch()
    assert all(view.layout_info.char_w >= fm.boundingRect(ch).width() + 2 for ch in 'MNWI')
    assert view.verticalScrollBar().pageStep() == view.viewport().height() // view.layout_info.line_h
    assert view.horizontalScrollBar().maximum() > 0
    view.horizontalScrollBar().setValue(view.horizontalScrollBar().maximum())
    app.processEvents()
    layout = view.layout_info
    x = layout.ascii_start + 5 * layout.char_w + layout.char_w // 2 - view.horizontalScrollBar().value()
    QTest.mouseClick(view.viewport(), Qt.MouseButton.LeftButton, pos=QPoint(x, layout.line_h // 2))
    assert view.selection_model.cursor == 5
    assert view.selection_model.focus_ascii
    view.navigate_to_offset(15)
    assert view.horizontalScrollBar().value() <= layout.ascii_start + 15 * layout.char_w
    view.resize(layout.total_width + 100, 340)
    QTest.qWait(10)
    assert view.horizontalScrollBar().maximum() == 0
    view.close()
    view.deleteLater()
    buffer.close()


def test_grid_finds_a_fixed_font_when_platform_default_is_proportional(app, monkeypatch):
    import hex_editor.hex_widget as module

    proportional = next(family for family in module.QFontDatabase.families()
                        if not module.QFontDatabase.isFixedPitch(family))
    monkeypatch.setattr(module.QFontDatabase, 'systemFont', lambda _: QFont(proportional))
    font = module.HexWidget._grid_font(QFont(proportional, 24))
    assert QFontInfo(font).fixedPitch()
    assert font.pointSize() == 24


@pytest.mark.parametrize('wrap', [False, True])
def test_gutter_tracks_font_size_baselines_and_scrolling(app, monkeypatch, wrap):
    import yaraxgui.editor.widget as module
    real_painter = module.QPainter
    painted = []
    class RecordingPainter:
        def __init__(self, *args):
            self.real = real_painter(*args)
        def __getattr__(self, name):
            return getattr(self.real, name)
        def drawText(self, *args):
            if len(args) == 2 and args[1].isdigit():
                painted.append((args[0], int(args[1]), QFont(self.real.font())))
            return self.real.drawText(*args)
    monkeypatch.setattr(module, 'QPainter', RecordingPainter)
    editor = YaraTextEdit()
    editor.setPlainText('\n'.join('word ' * 20 + str(i) for i in range(150)))
    editor.setLineWrapMode(editor.LineWrapMode.WidgetWidth if wrap else editor.LineWrapMode.NoWrap)
    editor.word_wrap_enabled = wrap
    editor.resize(660, 420)
    editor.show()
    for size in (12, 32, 48, 14):
        editor.setup_font('DejaVu Sans Mono', size)
        editor.verticalScrollBar().setValue(20)
        QTest.qWait(10)
        painted.clear()
        editor.line_number_area.grab()
        assert painted
        assert editor.viewportMargins().left() == editor.line_number_area.width()
        for point, number, font in painted:
            assert font.pointSize() == size
            block = editor.document().findBlockByNumber(number - 1)
            cursor = QTextCursor(block)
            baseline = editor.cursorRect(cursor).top() + editor.fontMetrics().ascent()
            assert abs(point.y() - baseline) <= 2
            assert point.x() >= 0
    editor.close()
    editor.deleteLater()
