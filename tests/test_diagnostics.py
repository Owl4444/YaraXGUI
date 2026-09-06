from PySide6.QtGui import QTextCharFormat, QTextCursor

from yaraxgui.editor.tabs import EditorTabWidget
from yaraxgui.editor.backend import Reply
from yaraxgui.editor.widget import YaraTextEdit


DIAGNOSTIC = {
    "range": {"start": {"line": 0, "character": 3},
              "end": {"line": 0, "character": 7}},
    "severity": 1,
    "message": "Unknown identifier",
}


def test_only_open_current_document_diagnostics_are_delivered(app):
    editor = YaraTextEdit()
    editor.setPlainText("rule r {condition: wrong}")
    editor._analysis_id = 3
    state = editor._document_state()
    def publish(request_id, snapshot):
        editor._on_backend_reply(Reply("analyze", request_id, snapshot,
            {"valid": False, "diagnostics": [DIAGNOSTIC]}))
    publish(2, state)
    publish(3, (-1, -1))
    assert not editor._diagnostics
    publish(3, state)
    assert editor._diagnostics == [DIAGNOSTIC]
    editor.shutdown_backend()
    editor.deleteLater()


def test_diagnostic_offsets_use_utf16_and_edits_clear_underlines(app):
    editor = YaraTextEdit()
    editor.setPlainText("😀 badx\ncondition: true")
    editor.set_diagnostics([DIAGNOSTIC])
    waves = [selection for selection in editor.extraSelections()
             if selection.format.underlineStyle() == QTextCharFormat.UnderlineStyle.WaveUnderline]
    assert len(waves) == 1
    assert waves[0].cursor.selectedText() == "badx"
    editor.moveCursor(QTextCursor.MoveOperation.End)
    editor.insertPlainText(" ")
    assert not editor._diagnostics
    assert not any(selection.format.underlineStyle() == QTextCharFormat.UnderlineStyle.WaveUnderline
                   for selection in editor.extraSelections())
    editor.deleteLater()


def test_diagnostics_do_not_land_during_unsent_edits_or_in_other_tabs(app):
    tabs = EditorTabWidget()
    editor = tabs.add_editor_tab("rule first { condition: true }")
    other = tabs.add_editor_tab("rule second { condition: true }")
    old_state = editor._document_state()
    editor.insertPlainText(" ")
    assert editor._analysis_timer.isActive()
    editor._analysis_id = 7
    editor._on_backend_reply(Reply("analyze", 7, old_state,
        {"valid": False, "diagnostics": [DIAGNOSTIC]}))
    assert not editor._diagnostics
    editor._on_backend_reply(Reply("analyze", 7, editor._document_state(),
        {"valid": False, "diagnostics": [DIAGNOSTIC]}))
    assert editor._diagnostics == [DIAGNOSTIC]
    assert not other._diagnostics
    tabs.deleteLater()
