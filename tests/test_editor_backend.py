import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QTextCursor
from PySide6.QtTest import QTest

import yaraxgui.editor.backend as editor_backend
from yaraxgui.editor.backend import EditorBackend, Reply
from yaraxgui.editor.tabs import EditorTabWidget
from yaraxgui.editor.widget import YaraTextEdit
from yarax_editor import FormatRunner, LanguageService


def until(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QTest.qWait(10)
    assert predicate(), "Background editor work did not finish"


@pytest.fixture
def editor(app, monkeypatch):
    monkeypatch.setattr(editor_backend, "format_runner", FormatRunner())
    widget = YaraTextEdit()
    widget.resize(900, 600)
    widget.show()
    widget.activateWindow()
    widget.setFocus()
    app.processEvents()
    yield widget
    until(lambda: not widget._backend._active)
    widget.shutdown_backend()
    widget.hide()
    widget.deleteLater()


def test_real_live_linting_uses_toolkit_unicode_ranges(editor):
    editor.setPlainText('rule r {meta: note = "😀 // /* */" condition: missing}')
    until(lambda: bool(editor._diagnostics))
    assert 'missing' in editor._diagnostics[0]['message']
    assert any(selection.cursor.selectedText() == 'missing' for selection in editor.extraSelections())
    editor.setPlainText('rule r {condition: with n = filesize : (n > 0)}')
    assert not editor._diagnostics
    editor.check_rule()
    until(lambda: 'analyze' not in editor._backend._active)
    assert not editor._diagnostics


def test_included_file_error_does_not_underline_current_file(editor, tmp_path):
    included = tmp_path / "common.yar"
    included.write_text('rule common {condition: missing}')
    # Forward slashes are accepted on Windows without YARA string escapes.
    editor.setPlainText(f'include "{included.as_posix()}"\nrule root {{condition: true}}')
    editor.check_rule()
    until(lambda: bool(editor._diagnostics))
    diagnostic = next(d for d in editor._diagnostics if 'missing' in d['message'])
    assert Path(diagnostic['origin']) == included
    assert 'range' not in diagnostic


def test_real_format_is_single_undo_step_and_preserves_cursor(editor):
    source = 'rule r {condition: with n = filesize : (n > 0)}'
    editor.setPlainText(source)
    editor.moveCursor(QTextCursor.MoveOperation.End)
    editor.format_rule()
    request_id = editor._format_id
    for _ in range(5):
        editor.format_rule()
        assert editor._format_id == request_id
    until(lambda: not editor.formatting)
    assert '\n    condition:\n' in editor.toPlainText()
    assert editor.document().isModified()
    editor.undo()
    assert editor.toPlainText() == source


@pytest.mark.parametrize('failure', [False, True])
def test_stale_format_result_or_error_cannot_touch_new_edits(editor, monkeypatch, failure):
    release, started = threading.Event(), threading.Event()
    def format(text, **kwargs):
        started.set()
        assert release.wait(4)
        if failure:
            raise ValueError('Stale formatting error')
        return 'rule stale {condition: false}'
    monkeypatch.setattr(editor_backend, 'format_runner', SimpleNamespace(format=format))
    editor.setPlainText('rule original {condition: true}')
    messages = []
    editor.language_status.connect(messages.append)
    editor.format_rule()
    until(started.is_set)
    editor.setPlainText('rule edited {condition: true}')
    release.set()
    until(lambda: not editor.formatting)
    assert editor.toPlainText() == 'rule edited {condition: true}'
    assert 'Stale formatting error' not in messages


def test_format_does_not_block_ui_and_global_slot_rejects_other_tabs(app, monkeypatch):
    release, started = threading.Event(), threading.Event()
    def format(text, **kwargs):
        started.set()
        assert release.wait(4)
        return text + '\n'
    monkeypatch.setattr(editor_backend, 'format_runner', SimpleNamespace(format=format))
    tabs = EditorTabWidget()
    first = tabs.add_editor_tab('rule first {condition: true}')
    second = tabs.add_editor_tab('rule second {condition: true}')
    messages = []
    second.language_status.connect(messages.append)
    first.format_rule()
    until(started.is_set)
    ticks = []
    QTimer.singleShot(10, lambda: ticks.append(True))
    until(lambda: bool(ticks))
    second.format_rule()
    assert not second.formatting
    assert 'another tab' in messages[-1]
    release.set()
    until(lambda: not first.formatting)
    assert first.toPlainText().endswith('\n')
    assert second.toPlainText() == 'rule second {condition: true}'
    first.shutdown_backend()
    second.shutdown_backend()
    tabs.deleteLater()


def test_language_requests_coalesce_and_closed_documents_drop_results(app, monkeypatch):
    release, started = threading.Event(), threading.Event()
    calls, replies = [], []
    def analyze(text, options):
        calls.append(text)
        if text == 'one':
            started.set()
            assert release.wait(4)
        return {'valid': True, 'diagnostics': []}
    monkeypatch.setattr(editor_backend, 'analyze_source', analyze)
    backend = EditorBackend()
    backend.finished.connect(replies.append)
    backend.request('analyze', 'one', 1)
    until(started.is_set)
    backend.request('analyze', 'two', 2)
    last = backend.request('analyze', 'three', 3)
    release.set()
    until(lambda: not backend._active)
    assert calls == ['one', 'three']
    assert len(replies) == 1 and replies[0].request_id == last
    backend.request('analyze', 'four', 4)
    backend.close()
    until(lambda: not backend._active)
    assert len(replies) == 1
    backend.deleteLater()


def test_large_file_controls_and_unicode_size_budget(editor):
    messages = []
    editor.language_status.connect(messages.append)
    editor.setPlainText('// ' + 'a' * (70 * 1024) + '\nrule r {condition: true}')
    assert not editor._analysis_timer.isActive()
    editor._trigger_completion()
    assert editor._last_completion_id == -1
    editor.check_rule()
    until(lambda: 'analyze' not in editor._backend._active)
    assert not editor._diagnostics
    source = '😀' * 70000
    editor.setPlainText(source)
    editor.format_rule()
    editor.check_rule()
    editor._trigger_completion(force=True)
    assert not editor.formatting
    assert '256 KiB' in messages[-1]
    assert editor.toPlainText() == source


def test_rule_snippet_mirrors_use_toolkit_and_undo(editor):
    editor.setPlainText('ru')
    editor.moveCursor(QTextCursor.MoveOperation.End)
    item = next(i for i in LanguageService().complete('ru', 2, explicit=True) if i.label == 'rule')
    editor._insert_completion(item.edit.text, item.snippet, (0, 2))
    assert editor.textCursor().selectedText() == 'rule_name'
    QTest.keyClicks(editor, 'myRule')
    QTest.keyClick(editor, Qt.Key.Key_Tab)
    assert editor.textCursor().selectedText() == 'a'
    QTest.keyClicks(editor, 'sig')
    assert '$sig = "text"' in editor.toPlainText()
    assert 'condition:\n        $sig' in editor.toPlainText()
    editor.undo()
    assert '$si = "text"' in editor.toPlainText()
    assert 'condition:\n        $si' in editor.toPlainText()


def test_nested_completion_docs_and_function_cursor(editor):
    text = 'import "pe" rule r {condition: pe.sections[0].raw'
    editor.setPlainText(text)
    editor.moveCursor(QTextCursor.MoveOperation.End)
    editor._trigger_completion(force=True)
    until(lambda: 'complete' not in editor._backend._active)
    assert any(i.label == 'raw_data_offset' for i in editor._completion_popup._items)
    assert all(i.documentation for i in editor._completion_popup._items)
    editor.setPlainText('import "math" rule r {condition: math.ent')
    editor.moveCursor(QTextCursor.MoveOperation.End)
    editor._trigger_completion(force=True)
    until(lambda: 'complete' not in editor._backend._active)
    item = next(i for i in editor._completion_popup._items if i.label == 'entropy')
    editor._insert_completion(item.insert_text, item.snippet, item.replacement)
    assert editor.toPlainText().endswith('math.entropy()')
    assert editor.textCursor().position() == len(editor.toPlainText()) - 1


@pytest.mark.parametrize('character', ['a', 'é', '😀'])
def test_automatic_threshold_is_utf8_and_resumes_on_undo(editor, character):
    limit = editor_backend.MAX_AUTOMATIC_BYTES
    source = character * (limit // len(character.encode('utf-8')))
    modes = []
    editor.large_file_mode_changed.connect(modes.append)
    editor.setPlainText(source)
    assert not editor.large_file_mode
    editor.moveCursor(QTextCursor.MoveOperation.End)
    editor.insertPlainText('x')
    assert editor.large_file_mode
    assert not editor._analysis_timer.isActive()
    assert not editor._completion_timer.isActive()
    editor.undo()
    assert editor.toPlainText() == source
    assert not editor.large_file_mode
    assert editor._analysis_timer.isActive()
    assert modes == [True, False]
    editor._analysis_timer.stop()


def test_large_file_typing_never_copies_or_lexes_source(editor, monkeypatch):
    editor.setPlainText('// padding\n' * 7000)
    editor.moveCursor(QTextCursor.MoveOperation.End)
    assert editor.large_file_mode
    def forbidden(*args, **kwargs):
        pytest.fail('Large-file typing scanned the full source')
    monkeypatch.setattr(editor, '_completion_text_position', forbidden)
    monkeypatch.setattr(editor, 'toPlainText', forbidden)
    monkeypatch.setattr(editor.document(), 'toPlainText', forbidden)
    QTest.keyClicks(editor, 'abc.({"')
    QTest.keyClick(editor, Qt.Key.Key_Return)
    QTest.keyClick(editor, Qt.Key.Key_Backspace)
    editor._trigger_completion()
    assert not editor._completion_timer.isActive()
    assert not editor._analysis_timer.isActive()
    assert not editor._backend._active
    cursor = editor.textCursor()
    cursor.setPosition(cursor.position() - 7, QTextCursor.MoveMode.KeepAnchor)
    assert cursor.selectedText() == 'abc.({"'


def test_large_mode_discards_queued_checks_and_ignores_active_reply(editor, monkeypatch):
    started, release = threading.Event(), threading.Event()
    calls = []
    def analyze(text, options):
        calls.append(text)
        started.set()
        assert release.wait(4)
        return {'valid': False, 'diagnostics': [{'message': 'obsolete'}]}
    monkeypatch.setattr(editor_backend, 'analyze_source', analyze)
    try:
        editor.setPlainText('first')
        editor.check_rule()
        until(started.is_set)
        editor.setPlainText('second')
        editor.check_rule()
        assert 'analyze' in editor._backend._pending
        editor.setPlainText('x' * (editor_backend.MAX_AUTOMATIC_BYTES + 1))
        assert not editor._backend._pending
    finally:
        release.set()
    until(lambda: not editor._backend._active)
    assert calls == ['first']
    assert not editor._diagnostics


def test_large_file_manual_format_remains_available(editor):
    source = '// ' + 'x' * (65 * 1024) + '\nrule r {condition: true}'
    editor.setPlainText(source)
    assert editor.large_file_mode
    editor.format_rule()
    until(lambda: not editor.formatting)
    assert '\n    condition:\n' in editor.toPlainText()
    assert editor.large_file_mode
    assert not editor._analysis_timer.isActive()
    editor.undo()
    assert editor.toPlainText() == source


def test_pair_crossing_threshold_does_not_restart_automatic_work(editor):
    editor.setPlainText(' ' * (editor_backend.MAX_AUTOMATIC_BYTES - 1))
    editor.moveCursor(QTextCursor.MoveOperation.End)
    QTest.keyClicks(editor, '(')
    assert editor.large_file_mode
    assert not editor._completion_timer.isActive()
    assert not editor._analysis_timer.isActive()


def test_large_mode_dismisses_pending_completion(editor, monkeypatch):
    from yaraxgui.editor.completer import CompletionItem
    editor.setPlainText('rule r {condition: tr')
    editor.moveCursor(QTextCursor.MoveOperation.End)
    editor._completion_popup.show_completions(
        [CompletionItem(label='true', insert_text='true', kind='keyword')], '', True)
    assert editor._completion_popup.isVisible()
    editor._completion_timer.start()
    editor.setPlainText('x' * (editor_backend.MAX_AUTOMATIC_BYTES + 1))
    assert not editor._completion_popup.isVisible()
    assert not editor._completion_timer.isActive()
    assert editor._last_completion_id == -1


def test_wrapping_and_gutter_follow_visible_lines_in_large_file(editor, app):
    from PySide6.QtWidgets import QPlainTextEdit
    source = ('// ' + 'word ' * 80 + '\n') * 2000
    editor.resize(500, 300)
    editor.setPlainText(source)
    editor.moveCursor(QTextCursor.MoveOperation.End)
    app.processEvents()
    assert isinstance(editor, QPlainTextEdit)
    assert editor.firstVisibleBlock().blockNumber() > 1900
    assert editor.line_number_area.width() == editor.line_number_area_width()
    position = editor.textCursor().position()
    assert editor.toggle_word_wrap()
    app.processEvents()
    assert editor.lineWrapMode() == QPlainTextEdit.LineWrapMode.WidgetWidth
    assert editor.textCursor().position() == position
    assert editor.firstVisibleBlock().blockNumber() > 1900
    assert not editor.toggle_word_wrap()
    assert editor.toPlainText() == source
    # Render the actual gutter at the end, exercising visible-block geometry.
    assert not editor.grab().isNull()


def test_small_file_smart_typing_resumes_after_large_file(editor):
    editor.setPlainText('x' * (64 * 1024 + 1))
    editor.setPlainText('rule r {condition: ')
    editor.moveCursor(QTextCursor.MoveOperation.End)
    QTest.keyClicks(editor, '(')
    assert editor.toPlainText().endswith('()')
    assert editor._completion_timer.isActive()
