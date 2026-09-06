from PySide6.QtCore import QPoint, Qt
from PySide6.QtTest import QTest

from hex_editor.transform_dialog import TransformDialog


def test_operation_search_after_opening_dropdown_and_no_stale_add(app):
    dialog = TransformDialog(True, 0, b'example')
    dialog.show()
    dialog.activateWindow()
    QTest.qWait(10)
    combo = dialog._op_combo
    try:
        QTest.mouseClick(combo, Qt.MouseButton.LeftButton,
                         pos=QPoint(combo.width() - 10, combo.height() // 2))
        popup = combo.completer().popup()
        assert popup.isVisible()
        QTest.keyClicks(popup, 'hUfFmAn')
        app.processEvents()
        assert combo.currentText() == 'hUfFmAn'
        assert not dialog._add_operation_btn.isEnabled()
        dialog._on_add_step()
        assert not dialog._step_widgets
        model = combo.completer().completionModel()
        names = [model.index(i, 0).data() for i in range(model.rowCount())]
        assert names and all('huffman' in name.lower() for name in names)
        popup.setCurrentIndex(model.index(0, 0))
        QTest.keyClick(popup, Qt.Key.Key_Return)
        app.processEvents()
        assert dialog.isVisible()
        assert not popup.isVisible()
        assert dialog._add_operation_btn.isEnabled()
        chosen = combo.selected_data()
        QTest.mouseClick(dialog._add_operation_btn, Qt.MouseButton.LeftButton)
        assert len(dialog._step_widgets) == 1
        assert dialog._step_widgets[0].spec.name == chosen

        combo.lineEdit().selectAll()
        QTest.keyClicks(combo.lineEdit(), 'not an existing operation')
        assert not dialog._add_operation_btn.isEnabled()
        QTest.keyClick(combo.lineEdit(), Qt.Key.Key_Escape)
        assert dialog.isVisible()
        assert combo.selected_data() == chosen
        assert dialog._add_operation_btn.isEnabled()

        combo.lineEdit().clear()
        assert not dialog._add_operation_btn.isEnabled()
        combo.setCurrentIndex(0)  # Category headings cannot be added as operations.
        assert combo.selected_data() is None
        dialog._on_add_step()
        assert len(dialog._step_widgets) == 1
    finally:
        combo.hidePopup()
        dialog.close()
        dialog.deleteLater()
