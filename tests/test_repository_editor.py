from unittest.mock import Mock

import pytest
from PySide6.QtWidgets import QDialog, QMessageBox, QPushButton

import yaraxgui.repository.local_store as local_rule_store
from yaraxgui.editor.tabs import EditorTabWidget
from yaraxgui.repository.editor import RepositoryEditorController
from yaraxgui.repository.dock import RuleRepoDock, _RuleMetadataDialog
from yaraxgui.repository.review import RuleUpdateReviewDialog


@pytest.fixture
def workspace(app, tmp_path, monkeypatch):
    monkeypatch.setattr(local_rule_store, 'prepare_local_database', lambda: tmp_path / 'rules.db')
    dock = RuleRepoDock()
    tabs = EditorTabWidget()
    tabs.add_editor_tab()
    controller = RepositoryEditorController(tabs, QPushButton())
    dock._edit_repository_rule = controller.open_rule
    warnings = Mock()
    monkeypatch.setattr(QMessageBox, 'warning', warnings)
    monkeypatch.setattr(RuleUpdateReviewDialog, 'exec', lambda self: QDialog.DialogCode.Accepted)
    rid = dock._repo_add(name='sample', rule_text='rule sample { condition: true }', tags='keep')['id']
    dock._on_search()
    dock._table.setCurrentCell(0, 0)
    dock._on_load()
    yield dock, tabs, controller, rid, warnings
    for index in range(tabs.count()):
        tabs.widget(index).shutdown_backend()
        tabs.widget(index)._recovery.discard()
    dock._local_repo.close()
    controller.bar.deleteLater()
    controller.deleteLater()
    dock.deleteLater()
    tabs.deleteLater()


def edit_text(editor, text):
    editor.selectAll()
    editor.insertPlainText(text)


def test_edit_and_update_preserve_identity_and_metadata(workspace):
    dock, tabs, controller, rid, warnings = workspace
    editor = tabs.current_editor()
    assert not editor.document().isModified()
    edit_text(editor, 'rule sample { condition: false }\nrule extra { condition: true }')
    other = dock._repo_add(name='other', rule_text='unchanged')['id']
    dock._on_search()
    dock._table.setCurrentCell(0, 0)  # selection changed to a different row
    assert controller.save(editor)
    assert dock._repo_get(rid)['rule_text'] == editor.toPlainText()
    assert dock._repo_get(rid)['tags'] == 'keep'
    assert dock._repo_get(other)['rule_text'] == 'unchanged'
    assert not editor.document().isModified()
    warnings.assert_not_called()


def test_reopen_focuses_draft_and_switching_tabs_changes_save_action(workspace):
    dock, tabs, controller, rid, _ = workspace
    editor = tabs.current_editor()
    editor.insertPlainText('// draft\n')
    before = editor.toPlainText()
    dock._open_repository_editor(dock._repo_get(rid))
    assert tabs.count() == 2
    assert tabs.current_editor() is editor
    assert editor.toPlainText() == before
    assert controller.save_button.text() == 'Update Repository'
    tabs.setCurrentIndex(0)
    assert controller.bar.isHidden()
    assert controller.save_button.text() == 'Save Rule'


def test_external_changes_or_deleted_rules_keep_draft(workspace):
    dock, tabs, controller, rid, warnings = workspace
    editor = tabs.current_editor()
    edit_text(editor, 'my draft')
    dock._repo_update(rid, rule_text='another editor')
    assert not controller.save(editor)
    assert dock._repo_get(rid)['rule_text'] == 'another editor'
    dock._repo_delete(rid)
    assert not controller.save(editor)
    assert editor.toPlainText() == 'my draft'
    assert editor.document().isModified()
    assert warnings.call_count == 2


def test_atomic_conflict_between_read_and_write_keeps_other_writer(workspace):
    dock, tabs, controller, rid, _ = workspace
    editor = tabs.current_editor()
    edit_text(editor, 'my draft')
    target = editor._repository_binding.target
    original = target.update

    def race(text, expected):
        dock._repo_update(rid, rule_text='concurrent writer')
        return original(text, expected)
    target.update = race
    assert not controller.save(editor)
    assert dock._repo_get(rid)['rule_text'] == 'concurrent writer'
    assert editor.document().isModified()


def test_switching_repository_never_writes_to_new_connection(workspace, monkeypatch):
    dock, tabs, controller, rid, _ = workspace
    editor = tabs.current_editor()
    edit_text(editor, 'my draft')
    dock._mode_combo.setCurrentIndex(1)
    dock._server_url = 'https://different.example'
    request = Mock(side_effect=AssertionError('must not contact another repository'))
    monkeypatch.setattr(dock, '_api', request)
    assert not controller.save(editor)
    request.assert_not_called()
    dock._mode_combo.setCurrentIndex(0)
    assert controller.save(editor)


def test_reload_cancel_and_close_save(workspace, monkeypatch):
    dock, tabs, controller, rid, _ = workspace
    editor = tabs.current_editor()
    edit_text(editor, 'my draft')
    monkeypatch.setattr(QMessageBox, 'question', lambda *args: QMessageBox.StandardButton.Cancel)
    controller.reload()
    assert editor.toPlainText() == 'my draft'
    monkeypatch.setattr(QMessageBox, 'question', lambda *args: QMessageBox.StandardButton.Save)
    assert tabs.confirm_close_editor(editor)
    assert dock._repo_get(rid)['rule_text'] == 'my draft'


def test_metadata_dialog_has_no_source_editor(app):
    from PySide6.QtWidgets import QPlainTextEdit
    dialog = _RuleMetadataDialog(name='sample')
    assert not dialog.findChildren(QPlainTextEdit)
    assert 'rule_text' not in dialog.metadata()
    dialog.deleteLater()


def test_cancel_review_preserves_rule_draft_and_binding(workspace, monkeypatch):
    dock, tabs, controller, rid, warnings = workspace
    editor = tabs.current_editor()
    before = dock._repo_get(rid)['rule_text']
    binding = editor._repository_binding
    edit_text(editor, 'my draft')

    def cancel(dialog):
        assert dialog._versions[1:] == [before, 'my draft']
        assert '-rule sample' in dialog._versions[0]
        assert '+my draft' in dialog._versions[0]
        assert dock._repo_get(rid)['rule_text'] == before
        return QDialog.DialogCode.Rejected
    monkeypatch.setattr(RuleUpdateReviewDialog, 'exec', cancel)
    assert not controller.save(editor)
    assert dock._repo_get(rid)['rule_text'] == before
    assert editor.toPlainText() == 'my draft'
    assert editor.document().isModified()
    assert editor._repository_binding is binding
    assert binding.rule['rule_text'] == before
    warnings.assert_not_called()


def test_draft_changes_during_review_require_a_new_review(workspace, monkeypatch):
    dock, tabs, controller, rid, warnings = workspace
    editor = tabs.current_editor()
    before = dock._repo_get(rid)['rule_text']
    edit_text(editor, 'reviewed draft')

    def review(dialog):
        edit_text(editor, 'unreviewed edit')
        return QDialog.DialogCode.Accepted
    monkeypatch.setattr(RuleUpdateReviewDialog, 'exec', review)
    assert not controller.save(editor)
    assert dock._repo_get(rid)['rule_text'] == before
    assert editor.toPlainText() == 'unreviewed edit'
    assert editor.document().isModified()
    assert 'draft changed during review' in warnings.call_args.args[2]


def test_repository_changes_while_reviewing_keep_both_versions(workspace, monkeypatch):
    dock, tabs, controller, rid, warnings = workspace
    editor = tabs.current_editor()
    edit_text(editor, 'my draft')

    def review(dialog):
        dock._repo_update(rid, rule_text='another writer')
        return QDialog.DialogCode.Accepted
    monkeypatch.setattr(RuleUpdateReviewDialog, 'exec', review)
    assert not controller.save(editor)
    assert dock._repo_get(rid)['rule_text'] == 'another writer'
    assert editor.toPlainText() == 'my draft'
    assert editor.document().isModified()
    assert 'repository changed during review' in warnings.call_args.args[2]


def test_cancel_review_prevents_tab_closing(workspace, monkeypatch):
    dock, tabs, controller, rid, _ = workspace
    editor = tabs.current_editor()
    edit_text(editor, 'my draft')
    monkeypatch.setattr(QMessageBox, 'question', lambda *args: QMessageBox.StandardButton.Save)
    monkeypatch.setattr(RuleUpdateReviewDialog, 'exec', lambda self: QDialog.DialogCode.Rejected)
    count = tabs.count()
    tabs._close_tab(tabs.currentIndex())
    assert tabs.count() == count
    assert tabs.current_editor() is editor
    assert editor.document().isModified()


def test_unchanged_rule_does_not_prompt_or_write(workspace, monkeypatch):
    dock, tabs, controller, rid, _ = workspace
    monkeypatch.setattr(RuleUpdateReviewDialog, 'exec', Mock(side_effect=AssertionError('no changes to review')))
    editor = tabs.current_editor()
    editor._repository_binding.target.update = Mock(side_effect=AssertionError('no changes to write'))
    assert controller.save(editor)
