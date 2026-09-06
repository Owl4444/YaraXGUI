from unittest.mock import Mock

import pytest
from PySide6.QtWidgets import QFileDialog, QMessageBox

from yaraxgui.editor.tabs import EditorTabWidget


@pytest.fixture
def tabs(app):
    widget = EditorTabWidget()
    yield widget
    widget.deleteLater()


def test_cancel_keeps_modified_tab(tabs, monkeypatch):
    editor = tabs.add_editor_tab("text")
    tabs.add_editor_tab()
    monkeypatch.setattr(QMessageBox, "question", lambda *a: QMessageBox.StandardButton.Cancel)
    tabs._close_tab(0)
    assert tabs.count() == 2
    assert editor.document().isModified()


def test_cancelled_save_prevents_window_close(tabs, monkeypatch):
    tabs.add_editor_tab("text")
    monkeypatch.setattr(QMessageBox, "question", lambda *a: QMessageBox.StandardButton.Save)
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a: ("", ""))
    assert not tabs.confirm_close_all()
    assert tabs.current_editor().document().isModified()


def test_save_failure_prevents_close(tabs, tmp_path, monkeypatch):
    tabs.add_editor_tab("text")
    monkeypatch.setattr(QMessageBox, "question", lambda *a: QMessageBox.StandardButton.Save)
    monkeypatch.setattr(QMessageBox, "critical", Mock())
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a: (str(tmp_path / "missing/file.yar"), ""))
    assert not tabs.confirm_close_all()
    assert tabs.current_editor().document().isModified()


def test_close_checks_inactive_tab_and_saves_it(tabs, tmp_path, monkeypatch):
    first = tabs.add_editor_tab("first")
    second = tabs.add_editor_tab("second", source_path="second.yar")
    target = tmp_path / "saved.yar"
    monkeypatch.setattr(QMessageBox, "question", lambda *a: QMessageBox.StandardButton.Save)
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a: (str(target), ""))
    assert tabs.confirm_close_all()
    assert target.read_text() == "first"
    assert not first.document().isModified()
    assert second.toPlainText() == "second"


def test_deleting_entire_file_is_still_a_change(tabs, tmp_path, monkeypatch):
    editor = tabs.add_editor_tab("original", source_path="original.yar")
    editor.selectAll()
    editor.insertPlainText("")
    assert editor.document().isModified()
    target = tmp_path / "empty.yar"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a: (str(target), ""))
    assert tabs.save_editor(editor) == str(target)
    assert target.read_text() == ""
    assert not editor.document().isModified()


def test_discarding_last_tab_resets_document_identity(tabs, monkeypatch):
    editor = tabs.add_editor_tab("text")
    old_epoch = editor._document_epoch
    monkeypatch.setattr(QMessageBox, "question", lambda *a: QMessageBox.StandardButton.Discard)
    tabs._close_tab(0)
    assert tabs.count() == 1
    assert not editor.toPlainText()
    assert not editor.document().isModified()
    assert editor._document_epoch != old_epoch
