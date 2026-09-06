from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QDialog

from yaraxgui.repository.review import RuleUpdateReviewDialog, rule_diff


def test_diff_shows_insertions_deletions_and_unchanged_context():
    text, coarse = rule_diff('rule a {\n  condition: true\n}\n', 'rule a {\n  condition: false\n}\n')
    assert not coarse
    assert ' rule a {\n' in text
    assert '-  condition: true\n' in text
    assert '+  condition: false\n' in text
    assert '@@ -1,3 +1,3 @@' in text
    assert '-removed\n' in rule_diff('removed\n', '')[0]
    assert '+added\n' in rule_diff('', 'added\n')[0]


def test_whitespace_and_missing_newline_are_visible():
    text, _ = rule_diff('a\r\nvalue ', 'a\nvalue\n')
    assert '-a[CR]\n' in text
    assert '-value \n\\ No newline at end of file' in text
    assert '+value\n' in text


def test_review_is_read_only_and_cancel_is_default(app):
    dialog = RuleUpdateReviewDialog('<rule>', 'Local repository', 'old', 'new')
    dialog.show()
    QTest.qWait(10)
    assert dialog._view.isReadOnly()
    assert dialog._cancel.isDefault()
    assert not dialog._confirm.isDefault()
    assert not dialog._confirm.autoDefault()
    dialog._mode.setCurrentIndex(1)
    assert dialog._view.toPlainText() == 'old'
    dialog._mode.setCurrentIndex(2)
    assert dialog._view.toPlainText() == 'new'
    dialog._show_whitespace(True)
    dialog._cancel.setFocus()
    QTest.keyClick(dialog._cancel, Qt.Key.Key_Return)
    assert dialog.result() == QDialog.DialogCode.Rejected
    assert not dialog.isVisible()
    dialog.deleteLater()


def test_confirm_button_accepts_and_escape_cancels(app):
    dialog = RuleUpdateReviewDialog('rule', 'remote.example', 'old', 'new')
    dialog.show()
    QTest.mouseClick(dialog._confirm, Qt.MouseButton.LeftButton)
    assert dialog.result() == QDialog.DialogCode.Accepted
    dialog.deleteLater()
    dialog = RuleUpdateReviewDialog('rule', 'remote.example', 'old', 'new')
    dialog.show()
    QTest.keyClick(dialog, Qt.Key.Key_Escape)
    assert dialog.result() == QDialog.DialogCode.Rejected
    assert not dialog.isVisible()
    dialog.deleteLater()


def test_large_review_is_paged_without_losing_changes(app):
    before = 'prefix\n' + 'old line\n' * 5000 + 'tail\n'
    after = 'prefix\n' + 'new line\n' * 5000 + 'tail\n'
    diff, coarse = rule_diff(before, after)
    assert coarse
    assert diff.count('-old line\n') == 5000
    assert diff.count('+new line\n') == 5000
    dialog = RuleUpdateReviewDialog('large', 'Local repository', before, after)
    assert len(dialog._pages) > 2
    rendered = []
    for page in range(len(dialog._pages) - 1):
        dialog._show_page(page)
        start, end = dialog._pages[page:page + 2]
        assert end - start <= dialog.PAGE_CHARS
        rendered.append(dialog._text[start:end])
    assert ''.join(rendered) == diff
    dialog.deleteLater()


def test_very_long_lines_and_unchanged_input(app):
    dialog = RuleUpdateReviewDialog('long', 'Local repository', 'x' * 300000, 'y' * 300000)
    assert len(dialog._pages) > 5
    assert all(b > a for a, b in zip(dialog._pages, dialog._pages[1:]))
    assert dialog._pages[-1] == len(dialog._versions[0])
    dialog.deleteLater()
    dialog = RuleUpdateReviewDialog('same', 'Local repository', 'unchanged', 'unchanged')
    assert not dialog._confirm.isEnabled()
    assert dialog._view.toPlainText() == 'No changes.\n'
    dialog.deleteLater()
