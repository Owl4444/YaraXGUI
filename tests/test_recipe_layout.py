import pytest
from PySide6.QtTest import QTest
from hex_editor.transform_dialog import TransformDialog
from hex_editor.transforms import find_spec


@pytest.mark.parametrize('width', [900, 1200])
def test_recipe_growth_does_not_shrink_previews_and_expand_keeps_contents(app, width):
    dialog = TransformDialog(True, 0, b'example input'*30)
    dialog.resize(width, 680)
    dialog.show()
    QTest.qWait(20)
    before_height = dialog._preview_in.height()
    for _ in range(12):
        dialog._add_step_widget(find_spec('NOT (bitwise)'), {})
    dialog._rebuild_step_combo()
    dialog._update_preview()
    QTest.qWait(20)
    assert dialog._preview_in.height() >= before_height - 10
    assert dialog._preview_out.height() >= 150
    assert dialog._preview_debug.isHidden()
    original = dialog._preview_in.toPlainText(), dialog._preview_out.toPlainText()
    width = dialog._preview_in.width()
    dialog._expand_preview.setChecked(True)
    QTest.qWait(20)
    assert dialog._recipe_box.isHidden()
    assert dialog._preview_in.width() > width
    dialog._zoom_previews(3)
    assert dialog._preview_in.font().pointSize() == dialog._preview_out.font().pointSize()
    assert original == (dialog._preview_in.toPlainText(), dialog._preview_out.toPlainText())
    dialog._expand_preview.setChecked(False)
    assert not dialog._recipe_box.isHidden()
    dialog._preview_debug.setPlainText('Transform error: invalid parameter')
    assert not dialog._preview_debug.isHidden()
    dialog._debug_toggle.setChecked(False)
    assert dialog._preview_debug.isHidden()
    dialog.close()
    dialog.deleteLater()
