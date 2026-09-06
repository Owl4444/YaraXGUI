"""Repository-backed editor tabs and their explicit update/reload workflow."""

from dataclasses import dataclass
from typing import Callable

from PySide6.QtCore import QObject, Qt
from PySide6.QtWidgets import QDialog, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPushButton, QWidget

from yaraxgui.repository.review import RuleUpdateReviewDialog


@dataclass
class RepositoryRuleTarget:
    identity: tuple
    location: str
    read: Callable
    update: Callable
    refreshed: Callable


@dataclass
class _Binding:
    target: RepositoryRuleTarget
    rule: dict


class RepositoryEditorController(QObject):
    def __init__(self, tabs, save_button, parent=None):
        super().__init__(parent)
        self.tabs = tabs
        self.save_button = save_button
        self.bar = QWidget()
        layout = QHBoxLayout(self.bar)
        layout.setContentsMargins(0, 0, 0, 0)
        self.label = QLabel()
        self.label.setTextFormat(Qt.TextFormat.PlainText)
        self.label.setWordWrap(True)
        layout.addWidget(self.label, 1)
        copy = QPushButton('Save Copy As…')
        copy.clicked.connect(self.save_copy)
        layout.addWidget(copy)
        reload = QPushButton('Reload from Repository')
        reload.clicked.connect(self.reload)
        layout.addWidget(reload)
        tabs.current_editor_changed.connect(self.refresh)
        self.refresh()

    def open_rule(self, target: RepositoryRuleTarget, rule: dict):
        # Reopening the same entry focuses its draft instead of replacing it.
        for index in range(self.tabs.count()):
            editor = self.tabs.widget(index)
            binding = getattr(editor, '_repository_binding', None)
            if binding and binding.target.identity == target.identity:
                self.tabs.setCurrentIndex(index)
                editor.setFocus()
                return editor
        editor = self.tabs.add_editor_tab(rule['rule_text'], '[Repository] ' + rule['name'])
        editor._repository_binding = _Binding(target, dict(rule))
        editor._repository_save = lambda: self.save(editor)
        editor.document().setModified(False)
        editor.document().modificationChanged.connect(self.refresh)
        self.refresh()
        editor.setFocus()
        return editor

    def refresh(self, *_):
        editor = self.tabs.current_editor()
        binding = getattr(editor, '_repository_binding', None)
        self.bar.setVisible(binding is not None)
        self.save_button.setText('Update Repository' if binding else 'Save Rule')
        self.save_button.setEnabled(not binding or editor.document().isModified())
        self.save_button.setToolTip(
            'Review changes and update this tab’s original repository entry (Ctrl+S).' if binding
            else 'Save this rule to a YARA file (Ctrl+S).')
        if binding:
            state = 'Unsaved changes' if editor.document().isModified() else 'Saved'
            self.label.setText(f"{binding.rule['name']} · {binding.target.location} · {state}")

    def save(self, editor) -> bool:
        binding = getattr(editor, '_repository_binding', None)
        if not binding:
            return False
        text = editor.toPlainText()
        if not text.strip():
            QMessageBox.warning(self.bar, 'Empty rule', 'The repository rule cannot be empty.')
            return False
        try:
            current = binding.target.read()
            if not current:
                raise RuntimeError('This rule was deleted. Use Add as New to save a new entry.')
            if current['rule_text'] != text:
                if current['rule_text'] != binding.rule['rule_text']:
                    raise RuntimeError(
                        'This rule changed in the repository after you opened it. Your edits '
                        'are still here. Save a copy before reloading the repository version.')
                review = RuleUpdateReviewDialog(
                    f"{current['name']} (ID {current['id']})", binding.target.location,
                    current['rule_text'], text, self.bar)
                try:
                    accepted = review.exec() == QDialog.DialogCode.Accepted
                finally:
                    review.deleteLater()
                if not accepted:
                    return False
                # Formatting/background callbacks may still edit a document while
                # a modal dialog is open. Only write exactly what was reviewed.
                if editor.toPlainText() != text or editor._repository_binding is not binding:
                    raise RuntimeError('The draft changed during review. Review the changes again before saving.')
                latest = binding.target.read()
                if not latest or latest['rule_text'] != current['rule_text']:
                    raise RuntimeError('The repository changed during review. Your draft was not saved. '
                                       'Save a copy before reloading the repository version.')
                binding.target.update(text, binding.rule['rule_text'])
            binding.rule = dict(current, rule_text=text)
            editor.document().setModified(False)
            self.tabs.setTabText(self.tabs.indexOf(editor), '[Repository] ' + current['name'])
            self.refresh()
        except Exception as exc:
            QMessageBox.warning(self.bar, 'Repository update failed', str(exc))
            return False
        # A refresh failure must not turn a successful write into a failed save.
        try:
            binding.target.refreshed()
        except Exception:
            self.label.setText(f"{binding.rule['name']} · Saved; refresh the repository list to see changes")
        return True

    def reload(self):
        editor = self.tabs.current_editor()
        binding = getattr(editor, '_repository_binding', None)
        if not binding:
            return
        if editor.document().isModified():
            answer = QMessageBox.question(
                self.bar, 'Reload repository rule',
                'Discard this tab’s unsaved changes and load the saved repository version?',
                QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel)
            if answer != QMessageBox.StandardButton.Discard:
                return
        try:
            rule = binding.target.read()
            if not rule:
                raise RuntimeError('This rule no longer exists in the repository.')
        except Exception as exc:
            QMessageBox.warning(self.bar, 'Reload failed', str(exc))
            return
        editor.setPlainText(rule['rule_text'])
        binding.rule = dict(rule)
        editor.document().setModified(False)
        self.tabs.setTabText(self.tabs.indexOf(editor), '[Repository] ' + rule['name'])
        self.refresh()

    def save_copy(self):
        editor = self.tabs.current_editor()
        binding = getattr(editor, '_repository_binding', None)
        if not binding:
            return
        path, _ = QFileDialog.getSaveFileName(self.bar, 'Save YARA copy', '',
                                             'YARA files (*.yar *.yara);;All files (*)')
        if not path:
            return
        try:
            from pathlib import Path
            from yaraxgui.recovery.store import atomic_write
            atomic_write(Path(path), editor.toPlainText().encode('utf-8'))
        except Exception as exc:
            QMessageBox.warning(self.bar, 'Save copy failed', str(exc))
