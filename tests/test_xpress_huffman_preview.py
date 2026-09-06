from PySide6.QtWidgets import QDialog, QMessageBox
import pytest

from hex_editor.transform_dialog import TransformDialog
from hex_editor.transforms import RecipeStep


@pytest.fixture(autouse=True)
def preview_settings(tmp_path, monkeypatch):
    import hex_editor.transform_dialog as dialog_module
    monkeypatch.setattr(dialog_module, '_settings_path', lambda: tmp_path / 'settings.json')


def _stream():
    header = bytearray(256)
    header[48], header[49], header[128], header[143] = 0x30, 0x23, 2, 0x20
    return bytes(header) + bytes.fromhex('a8 dc 00 00 ff 26 01')


def _recipe():
    return RecipeStep('XPRESS Huffman decompress', {'expected_size': '300'})


def test_preview_display_limit_does_not_truncate_compressed_input(app):
    dialog = TransformDialog(True, 0, _stream(), initial_steps=[_recipe()])
    try:
        dialog._preview_size_spin.setValue(16)
        dialog._update_preview()
        assert '300 bytes' in dialog._preview_out_label.text()
        assert '61 62 63' in dialog._preview_out.toPlainText()
        assert not dialog._preview_debug.toPlainText()
    finally:
        dialog.close()
        dialog.deleteLater()


def test_complete_input_is_kept_through_preceding_recipe_steps(app):
    dialog = TransformDialog(True, 0, _stream(), initial_steps=[
        RecipeStep('NOT (bitwise)'), RecipeStep('NOT (bitwise)'), _recipe(),
    ])
    try:
        dialog._preview_size_spin.setValue(16)
        dialog._focused_step = 2
        dialog._update_preview()
        assert '300 bytes' in dialog._preview_out_label.text()
        assert not dialog._preview_debug.toPlainText()
    finally:
        dialog.close()
        dialog.deleteLater()


def test_partial_preview_does_not_block_apply(app, monkeypatch):
    dialog = TransformDialog(True, 0, _stream()[:256],
                             initial_steps=[_recipe()], probe_complete=False)
    try:
        dialog._update_preview()
        assert 'Preview unavailable' in dialog._preview_debug.toPlainText()
        assert 'full selected scope' in dialog._preview_debug.toPlainText()

        def unexpected_warning(*args):
            raise AssertionError('Apply must not validate decompression on a truncated sample')
        monkeypatch.setattr(QMessageBox, 'warning', unexpected_warning)
        dialog._on_apply()
        assert dialog.result() == QDialog.DialogCode.Accepted
        assert dialog.get_request().steps == [_recipe()]
    finally:
        dialog.close()
        dialog.deleteLater()
