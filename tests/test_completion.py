import pytest
from PySide6.QtCore import QObject, Signal, Qt
from PySide6.QtGui import QTextCursor
from PySide6.QtTest import QTest

from yaraxgui.editor.backend import Reply
from yarax_editor import LanguageService, Completion, TextEdit, Span
from yaraxgui.editor.widget import YaraTextEdit


class FakeBackend(QObject):
    finished = Signal(object)

    def __init__(self):
        super().__init__()
        self.request_id = 0

    def request(self, *args, **kwargs):
        self.request_id += 1
        return self.request_id

    def close(self):
        pass

    def complete(self, request_id, items):
        self.finished.emit(Reply("complete", request_id, None,
            {"items": items, "signature": None, "hover": None}))


def attach(editor, client):
    editor._backend.finished.disconnect(editor._on_backend_reply)
    editor._backend = client
    client.finished.connect(editor._on_backend_reply)


def trigger(editor, force=False):
    editor._trigger_completion(force)
    for _ in range(500):
        if "complete" not in editor._backend._active:
            return
        QTest.qWait(10)
    pytest.fail("Completion worker did not finish")


@pytest.fixture
def editor(app):
    widget = YaraTextEdit()
    widget.resize(800, 500)
    widget.show()
    widget.activateWindow()
    widget.setFocus()
    app.processEvents()
    yield widget
    widget.shutdown_backend()
    widget.hide()
    widget.deleteLater()


def put(editor, text):
    editor.setPlainText(text)
    editor.moveCursor(QTextCursor.MoveOperation.End)


@pytest.mark.parametrize("source", ['// "{}', '/* "{}', '"literal {}', '"""\nmetadata {}'])
def test_backspace_in_noncode_does_not_delete_the_following_brace(editor, source):
    put(editor, source)
    editor.moveCursor(QTextCursor.MoveOperation.Left)
    QTest.keyClick(editor, Qt.Key.Key_Backspace)
    assert editor.toPlainText() == source[:-2] + "}"


@pytest.mark.parametrize("source", ['// ""', '/* ""', r'"escaped \"'])
def test_typing_quote_in_comment_or_after_escape_does_not_skip_existing_quote(editor, source):
    put(editor, source)
    editor.moveCursor(QTextCursor.MoveOperation.Left)
    QTest.keyClicks(editor, '"')
    assert editor.toPlainText() == source[:-1] + '""'


@pytest.mark.parametrize("source", ['// comment {}', '/* comment {}', '"""\n    metadata {}'])
def test_enter_in_comment_or_metadata_does_not_expand_braces(editor, source):
    put(editor, source)
    editor.moveCursor(QTextCursor.MoveOperation.Left)
    QTest.keyClick(editor, Qt.Key.Key_Return)
    indent = "    " if "metadata" in source else ""
    assert editor.toPlainText() == source[:-1] + "\n" + indent + "}"


def test_enter_expands_with_expression_body(editor):
    source = "rule r {\n    condition:\n        with value = filesize : ()"
    put(editor, source)
    editor.moveCursor(QTextCursor.MoveOperation.Left)
    QTest.keyClick(editor, Qt.Key.Key_Return)
    assert editor.toPlainText().endswith(": (\n            \n        )")


def test_typing_complete_keyword_dismisses_immediately(editor):
    put(editor, "rule r { condition: fil")
    trigger(editor)
    assert editor._completion_popup.isVisible()
    QTest.keyClicks(editor, "esize")
    assert editor.toPlainText().endswith("filesize")
    assert not editor._completion_popup.isVisible()
    trigger(editor)
    assert not editor._completion_popup.isVisible()


@pytest.mark.parametrize("text", ["rule", "condition", "rule r { condition: pe.entry_point"])
def test_complete_tokens_do_not_offer_snippets_or_longer_variants(editor, text):
    put(editor, text)
    trigger(editor)
    assert not editor._completion_popup.isVisible()


def test_enter_does_not_accept_unsolicited_suggestion(editor):
    put(editor, "rule r { condition: fil")
    trigger(editor)
    QTest.keyClick(editor, Qt.Key.Key_Return)
    assert "filesize" not in editor.toPlainText()
    assert "fil\n" in editor.toPlainText()
    assert not editor._completion_popup.isVisible()


def test_manual_completion_after_dot_can_be_accepted(editor):
    put(editor, 'import "pe" rule r { condition: pe')
    QTest.keyClicks(editor, ".")
    trigger(editor)
    assert editor._completion_popup.isVisible()
    trigger(editor, force=True)
    assert editor._completion_popup._explicit
    expected = editor._completion_popup._items[0].insert_text
    QTest.keyClick(editor, Qt.Key.Key_Return)
    assert expected in editor.toPlainText()
    assert not editor._completion_timer.isActive()


@pytest.mark.parametrize("action", ["escape", "cursor", "punctuation", "hide", "focus"])
def test_delayed_backend_cannot_resurrect_dismissed_completion(editor, app, action):
    client = FakeBackend()
    attach(editor, client)
    put(editor, "rule r { condition: fil")
    editor._trigger_completion()
    request_id = client.request_id
    if action == "escape":
        QTest.keyClick(editor, Qt.Key.Key_Escape)
    elif action == "cursor":
        QTest.keyClick(editor, Qt.Key.Key_Left)
    elif action == "punctuation":
        QTest.keyClicks(editor, " ")
    elif action == "hide":
        editor.hide()
    else:
        editor.clearFocus()
    client.complete(request_id, [Completion("filesize", "keyword", TextEdit(Span(20, 23), "filesize"))])
    assert not editor._completion_popup.isVisible()
    assert not editor._completion_timer.isActive()


def test_previous_request_cannot_replace_current_candidates(editor):
    client = FakeBackend()
    attach(editor, client)
    put(editor, "rule r { condition: fil")
    editor._trigger_completion()
    old_id = client.request_id
    QTest.keyClicks(editor, "e")
    client.complete(old_id, [Completion("filter_wrong", "keyword", TextEdit(Span(20, 23), "filter_wrong"))])
    assert all(i.label != "filter_wrong" for i in editor._completion_popup._items)


@pytest.mark.parametrize("text,allowed", [
    ('rule r { strings: $a = "abc', False),
    ('rule r { strings: $a = /abc[//]def', False),
    ('rule r { strings: $a = { 01 ??', False),
    ('rule r { /* comment', False),
    ('rule r { // comment', False),
    ('rule r { strings: $a = "http://site/*"\n condition: fil', True),
    ('rule r { strings: $a = /abc\\/def/\n condition: fil', True),
    ('import "p', True),
])
def test_lexical_suppression(text, allowed):
    assert bool(LanguageService().complete(text, len(text))) == allowed


def test_import_completion_reuses_paired_quote(editor):
    put(editor, 'import "p"')
    editor.moveCursor(QTextCursor.MoveOperation.Left)
    trigger(editor, force=True)
    item = next(i for i in editor._completion_popup._items if i.label == "pe")
    editor._insert_completion(item.insert_text, item.snippet, item.replacement)
    assert editor.toPlainText() == 'import "pe"'


def test_manual_completion_replaces_remaining_identifier(editor):
    put(editor, "rule r { condition: filesze")
    editor.moveCursor(QTextCursor.MoveOperation.Left)
    editor.moveCursor(QTextCursor.MoveOperation.Left)
    editor._insert_completion("filesize", False)
    assert editor.toPlainText().endswith("filesize")


def test_unicode_before_completion_does_not_shift_replacement(editor):
    put(editor, '// 😀\nrule r { condition: fil')
    trigger(editor)
    assert editor._completion_popup.isVisible()
    editor._insert_completion("filesize", False)
    assert editor.toPlainText() == '// 😀\nrule r { condition: filesize'


def test_snippet_tabstops_follow_growing_placeholder(editor):
    put(editor, "")
    editor._insert_completion("${1:name} = ${2:value}; $0", True)
    assert editor.textCursor().selectedText() == "name"
    QTest.keyClicks(editor, "longer_name")
    QTest.keyClick(editor, Qt.Key.Key_Tab)
    assert editor.textCursor().selectedText() == "value"


def test_backend_text_edit_uses_validated_replacement_range(editor):
    client = FakeBackend()
    attach(editor, client)
    put(editor, 'import "pe" rule r { condition: pe.ent')
    editor._trigger_completion()
    start = editor.toPlainText().index("pe.ent")
    client.complete(client.request_id, [Completion("entry_point", "field",
        TextEdit(Span(start, len(editor.toPlainText())), "pe.entry_point"))])
    item = next(i for i in editor._completion_popup._items if i.label == "entry_point")
    editor._insert_completion(item.insert_text, item.snippet, item.replacement)
    assert editor.toPlainText().endswith("pe.entry_point")
    assert "pe.pe" not in editor.toPlainText()


def test_changing_document_identity_invalidates_completion(editor):
    client = FakeBackend()
    attach(editor, client)
    put(editor, "rule r { condition: fil")
    editor._trigger_completion()
    request_id = client.request_id
    editor.set_source_path("saved.yar")
    client.complete(request_id, [Completion("filesize", "keyword", TextEdit(Span(20, 23), "filesize"))])
    assert not editor._completion_popup.isVisible()


def test_typing_unrelated_text_drops_stale_popup(editor):
    put(editor, "rule r { condition: fil")
    trigger(editor)
    QTest.keyClicks(editor, "zz")
    assert not editor._completion_popup.isVisible()


def test_accepting_completion_is_one_undo_step(editor):
    put(editor, 'import "p"')
    editor.moveCursor(QTextCursor.MoveOperation.Left)
    editor._insert_completion('pe"', False)
    assert editor.toPlainText() == 'import "pe"'
    editor.undo()
    assert editor.toPlainText() == 'import "p"'


@pytest.mark.parametrize("before,typed", [
    ("// comment ", '"'), ("/* comment ", "("),
    ('rule r { strings: $a = "text', "["),
    ('rule r { strings: $a = /abc', "("),
])
def test_literal_typing_does_not_insert_unwanted_pairs(editor, before, typed):
    put(editor, before)
    QTest.keyClicks(editor, typed)
    assert editor.toPlainText() == before + typed


def test_leaving_placeholder_ends_snippet_navigation(editor):
    put(editor, "")
    editor._insert_completion("${1:name} = ${2:value}; $0", True)
    QTest.keyClick(editor, Qt.Key.Key_End)
    assert not editor._snippet_tabstops
