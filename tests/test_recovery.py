import json
import os
from pathlib import Path
import random
import subprocess
import sys
import time

import pytest
from PySide6.QtGui import QCloseEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QFileDialog, QMessageBox
from hex_editor.hex_data_buffer import HexDataBuffer
from hex_editor.hex_editor_window import HexEditorWindow
from yaraxgui.editor.tabs import EditorTabWidget
from yaraxgui.recovery.store import DraftRecord, HexJournal, recoverable_entries, restore_hex, atomic_write


def until(predicate, timeout=10):
    end = time.monotonic() + timeout
    while not predicate() and time.monotonic() < end:
        QTest.qWait(10)
    assert predicate()


def test_hex_journal_replays_overwrite_insert_delete_and_undo(app):
    buffer = HexDataBuffer()
    initial = b'abcdefghij'*100
    buffer.open_bytes(initial)
    buffer.enable_recovery()
    expected = bytearray(initial)
    rng = random.Random(42)
    for _ in range(120):
        start = rng.randrange(len(expected)+1)
        removed = rng.randrange(min(20, len(expected)-start)+1)
        new = rng.randbytes(rng.randrange(20))
        buffer.replace_range(start, start+removed-1, new)
        expected[start:start+removed] = new
    journal = buffer.recovery
    journal.finish()
    journal.thread.join(5)
    assert not journal.error
    assert journal.saved_sequence == 120
    recovered = restore_hex(journal.folder)
    assert recovered.read_bytes() == expected
    assert (journal.folder/'base.bin').read_bytes() == initial
    buffer.close()


def test_recovery_survives_abrupt_process_exit(app):
    code = '''
import os
from PySide6.QtCore import QCoreApplication
from yaraxgui.recovery.store import DraftRecord
from hex_editor.hex_data_buffer import HexDataBuffer
app=QCoreApplication([])
draft=DraftRecord()
draft.submit('rule recovered {condition: true}', {'source':'original.yar','cursor':4})
draft.finish(); draft.thread.join(5)
buf=HexDataBuffer();buf.open_bytes(b'original');buf.enable_recovery()
buf.replace_range(0,7,b'recovered bytes')
buf.recovery.finish();buf.recovery.thread.join(5)
assert not buf.recovery.error
os._exit(17)
'''
    result = subprocess.run([sys.executable, '-c', code], timeout=15, capture_output=True)
    assert result.returncode == 17, result.stderr.decode()
    entries = recoverable_entries()
    assert len(entries) == 2
    for folder, meta in entries:
        if meta['kind'] == 'yara':
            assert (folder/'draft.yar').read_text() == 'rule recovered {condition: true}'
        else:
            assert restore_hex(folder).read_bytes() == b'recovered bytes'


def test_running_session_is_not_offered(app):
    record = DraftRecord()
    record.submit('unsaved', {'source':'test.yar'})
    record.finish()
    record.thread.join(3)
    assert not recoverable_entries()


def test_corrupt_hex_baseline_is_retained(app):
    journal = HexJournal(b'original', 'sample.bin')
    journal.record(0, 1, b'X')
    journal.finish()
    journal.thread.join(3)
    (journal.folder/'base.bin').write_bytes(b'corrupt')
    with pytest.raises(ValueError, match='damaged'):
        restore_hex(journal.folder)
    assert (journal.folder/'edits.sqlite').exists()


def test_draft_capture_and_successful_save_cleanup(app, tmp_path, monkeypatch):
    tabs = EditorTabWidget()
    editor = tabs.add_editor_tab('rule draft {condition: true}')
    editor._recovery.capture()
    record = editor._recovery.record
    until(lambda: (record.folder/'meta.json').exists())
    assert (record.folder/'draft.yar').read_text() == editor.toPlainText()
    destination = tmp_path/'saved.yar'
    monkeypatch.setattr(QFileDialog, 'getSaveFileName', lambda *a: (str(destination), ''))
    assert tabs.save_editor(editor)
    record.thread.join(3)
    assert not record.folder.exists()
    editor.shutdown_backend()
    tabs.deleteLater()


def test_failed_atomic_draft_write_retains_previous_version(app, tmp_path, monkeypatch):
    path = tmp_path/'draft.yar'
    atomic_write(path, b'original')
    import yaraxgui.recovery.store as recovery_store
    def fail(*a):
        raise OSError('disk full')
    monkeypatch.setattr(recovery_store.os, 'replace', fail)
    with pytest.raises(OSError):
        atomic_write(path, b'new text')
    assert path.read_bytes() == b'original'
    assert list(tmp_path.iterdir()) == [path]


@pytest.fixture
def window(app, monkeypatch):
    widget = HexEditorWindow()
    widget.open_bytes(b'hello', 'sample.bin')
    yield widget
    monkeypatch.setattr(QMessageBox, 'question', lambda *a: QMessageBox.StandardButton.Discard)
    widget.close()
    app.processEvents()


def test_hex_close_cancel_preserves_work(window, monkeypatch):
    window._buffer.write_bytes(0, b'H')
    monkeypatch.setattr(QMessageBox, 'question', lambda *a: QMessageBox.StandardButton.Cancel)
    event = QCloseEvent()
    window.closeEvent(event)
    assert not event.isAccepted()
    assert window._buffer.read(0, 5) == b'Hello'


def test_switch_file_and_navigation_cancel_preserve_old_buffer(window, tmp_path, monkeypatch):
    path = tmp_path/'new.bin'
    path.write_bytes(b'other')
    old = window._buffer
    old.write_bytes(0, b'H')
    monkeypatch.setattr(QMessageBox, 'question', lambda *a: QMessageBox.StandardButton.Cancel)
    assert not window.open_file(str(path))
    assert window._buffer is old
    assert not window.open_file(str(tmp_path/'missing'))
    assert window._buffer is old
    window.set_file_list(['sample.bin', str(path)], 'sample.bin')
    window._nav_next()
    assert window._file_index == 0
    assert window._buffer is old


def test_cancelled_save_as_does_not_close_modified_hex(window, monkeypatch):
    window._buffer.write_bytes(0, b'H')
    monkeypatch.setattr(QMessageBox, 'question', lambda *a: QMessageBox.StandardButton.Save)
    monkeypatch.setattr(QFileDialog, 'getSaveFileName', lambda *a: ('',''))
    event = QCloseEvent()
    window.closeEvent(event)
    assert not event.isAccepted()
    assert window._has_unsaved()


def test_empty_modified_file_can_be_saved_and_clears_dirty_state(window, tmp_path, monkeypatch):
    window._buffer.replace_range(0,4,b'')
    destination = tmp_path/'empty.bin'
    monkeypatch.setattr(QFileDialog,'getSaveFileName',lambda *a:(str(destination),''))
    assert window._on_save_as()
    assert destination.read_bytes() == b''
    assert not window._has_unsaved()


def test_failed_hex_save_does_not_damage_existing_file(window, tmp_path, monkeypatch):
    window._buffer.write_bytes(0, b'H')
    destination = tmp_path/'saved.bin'
    destination.write_bytes(b'valuable')
    import hex_editor.hex_data_buffer as module
    monkeypatch.setattr(module.os,'replace', lambda *a: (_ for _ in ()).throw(OSError('disk full')))
    assert not window._buffer.save_to(str(destination))
    assert destination.read_bytes() == b'valuable'
    assert window._has_unsaved()


def test_recovery_failure_does_not_prevent_editing(app, monkeypatch):
    import yaraxgui.recovery.store as recovery_store
    monkeypatch.setattr(recovery_store, 'HexJournal', lambda *a, **kw: (_ for _ in ()).throw(OSError('disk full')))
    buffer = HexDataBuffer()
    buffer.open_bytes(b'hello')
    buffer.enable_recovery()
    buffer.write_bytes(0,b'H')
    assert buffer.read(0,5) == b'Hello'
    assert 'disk full' in buffer.recovery.error
    buffer.close()


def test_post_save_recovery_rejects_changed_baseline(app, tmp_path):
    buffer = HexDataBuffer()
    buffer.open_bytes(b'hello')
    buffer.enable_recovery()
    buffer.write_bytes(0,b'H')
    path = tmp_path/'saved.bin'
    assert buffer.save_to(str(path))
    buffer.mark_saved(str(path))
    path.write_bytes(b'unrelated')
    buffer.write_bytes(1,b'A')
    assert buffer.read(0,5) == b'HAllo'
    assert 'changed externally' in buffer.recovery.error
    buffer.close()


def test_draft_io_failure_reports_without_more_typing(app, monkeypatch):
    import yaraxgui.recovery.store as recovery_store
    def fail(*a, **kw):
        raise OSError('disk full')
    monkeypatch.setattr(recovery_store, 'atomic_write', fail)
    tabs = EditorTabWidget()
    editor = tabs.add_editor_tab('rule unsaved {condition: true}')
    editor._recovery.capture()
    until(lambda: bool(editor._recovery.error))
    assert 'disk full' in editor._recovery.error
    editor._recovery.discard()
    editor.shutdown_backend()
    tabs.deleteLater()


def test_failed_yara_save_preserves_original_and_recovery(app, tmp_path, monkeypatch):
    import yaraxgui.recovery.store as recovery_store
    path = tmp_path/'rule.yar'
    path.write_text('original')
    tabs = EditorTabWidget()
    editor = tabs.add_editor_tab('rule changed {condition: true}')
    editor._recovery.capture()
    until(lambda: (editor._recovery.record.folder/'meta.json').exists())
    monkeypatch.setattr(QFileDialog,'getSaveFileName',lambda *a:(str(path),''))
    monkeypatch.setattr(QMessageBox,'critical', lambda *a: None)
    monkeypatch.setattr(recovery_store.os,'replace',lambda *a: (_ for _ in ()).throw(OSError('disk full')))
    assert tabs.save_editor(editor) is None
    assert path.read_text() == 'original'
    assert editor.document().isModified()
    assert editor._recovery.record is not None
    editor._recovery.discard()
    editor.shutdown_backend()
    tabs.deleteLater()


def test_edit_controller_undo_and_redo_are_journaled(app):
    from hex_editor.edit_controller import EditController
    buffer = HexDataBuffer()
    buffer.open_bytes(b'abcdefgh')
    buffer.enable_recovery()
    editor = EditController()
    editor.set_buffer(buffer)
    editor.overwrite_byte(0, ord('Z'))
    editor.insert_bytes(2, b'1234')
    editor.delete_at(6, 2)
    editor.undo()
    editor.undo()
    editor.redo()
    expected = buffer.read(0, buffer.size())
    journal = buffer.recovery
    journal.finish()
    journal.thread.join(3)
    assert restore_hex(journal.folder).read_bytes() == expected
    buffer.close()
