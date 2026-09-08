import os
import time
import threading
from pathlib import Path

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtTest import QTest
from hex_editor.hex_data_buffer import HexDataBuffer
from hex_editor.analysis_jobs import AnalysisJob, _ACTIVE
from hex_editor.analysis_worker import extract_strings, search_matches, compile_pattern, CHUNK_SIZE
from hex_editor.string_extractor import StringResultsWidget
from hex_editor.hex_search import HexSearchDialog
from hex_editor.analysis_results import ResultsModel


def until(predicate, timeout=10):
    end = time.monotonic() + timeout
    while not predicate() and time.monotonic() < end:
        QTest.qWait(10)
        # qWait processes Qt events but can retain the GIL; let the Python
        # supervisor drain worker batches instead of starving it on Windows.
        time.sleep(.001)
    assert predicate()


@pytest.fixture
def buffer():
    value = HexDataBuffer()
    yield value
    for job in list(_ACTIVE):
        job.cancel()
    until(lambda: not _ACTIVE)
    value.close()


def strings(data, **kwargs):
    return list(extract_strings(data, dict(min_length=4, **kwargs), lambda: False, lambda _: None))


def search(data, **kwargs):
    return list(search_matches(data, kwargs, lambda: False, lambda _: None))


def test_string_offsets_lengths_and_both_utf16_alignments():
    for alignment in (0, 1):
        raw = b'\xff' * alignment + 'hello\nworld'.encode('utf-16-le') + b'\xff\xff'
        assert strings(raw, ascii=False) == [(alignment, 22, 'UTF-16LE', 'hello\nworld')]
    assert strings(b'abcd\0efgh', unicode=False) == [(0,4,'ASCII','abcd'),(5,4,'ASCII','efgh')]


def test_strings_cross_chunks_and_bound_giant_preview():
    data = b'\x01' * (CHUNK_SIZE-3) + b'A' * (CHUNK_SIZE*3) + b'\0'
    rows = strings(data, unicode=False)
    assert rows == [(CHUNK_SIZE-3, CHUNK_SIZE*3, 'ASCII', 'A'*256)]
    data = b'\xff'*(CHUNK_SIZE-1) + ('wide'*100000).encode('utf-16-le') + b'\xff\xff'
    rows = strings(data, ascii=False)
    assert rows == [(CHUNK_SIZE-1, 800000, 'UTF-16LE', 'wide'*64)]


def test_search_real_file_boundaries_and_zero_length_matches():
    data = b'x'* (CHUNK_SIZE-2) + b'abcdef' + b'x'*CHUNK_SIZE
    assert search(data, kind='text', pattern='abcdef')[0][:2] == (CHUNK_SIZE-2, 6)
    assert not search(data, kind='regex', pattern='^abcdef')
    assert search(data, kind='regex', pattern='(?<=xx)abcdef')[0][:2] == (CHUNK_SIZE-2,6)
    assert [r[0] for r in search(b'aba',kind='regex',pattern='(?=a)')] == [0,2]
    assert search(b'ababa',kind='text',pattern='ba', mode='previous', start=4)[0][:2] == (3,2)


@pytest.mark.parametrize('pattern', ['gg', '123', '1', '?? zz'])
def test_invalid_hex_patterns_report_error(pattern):
    with pytest.raises(ValueError):
        compile_pattern(dict(kind='hex', pattern=pattern))


def test_snapshot_reads_current_edits_and_searches_offset_zero(app, buffer):
    buffer.open_bytes(b'abcdef')
    buffer.write_bytes(0, b'HELLO!')
    widget = HexSearchDialog(buffer)
    widget._tabs.setCurrentIndex(1)
    widget._text_input.setText('HELLO')
    widget._find_next()
    until(lambda: widget._controller.job is None)
    assert widget._model.rows[0][:2] == (0, 5)
    assert widget._last_offset == 0
    widget.close()
    widget.deleteLater()


def test_pathological_regex_cancel_is_responsive_and_process_dies(app, buffer):
    buffer.open_bytes(b'a'*500000 + b'!')
    widget = HexSearchDialog(buffer)
    widget._tabs.setCurrentIndex(2)
    widget._regex_input.setText('(a+)+$')
    widget._find_all()
    job = widget._controller.job
    until(lambda: job.process is not None and job.process.pid is not None)
    QTest.qWait(250)
    ticks = []
    QTimer.singleShot(0, lambda: ticks.append(True))
    started = time.monotonic()
    widget._controller.cancel()
    assert time.monotonic() - started < .1
    until(lambda: widget._controller.job is None, timeout=3)
    assert ticks
    assert 'Cancelled' in widget._status.text()
    assert time.monotonic() - started < 2
    widget.deleteLater()


def test_worker_crash_does_not_kill_gui(app, buffer):
    buffer.open_bytes(b'a'*500000 + b'!')
    widget = HexSearchDialog(buffer)
    widget._tabs.setCurrentIndex(2)
    widget._regex_input.setText('(a+)+$')
    widget._find_all()
    job = widget._controller.job
    until(lambda: job.process is not None and job.process.pid is not None)
    job.process.kill()
    until(lambda: widget._controller.job is None)
    assert 'Error:' in widget._status.text()
    assert widget._btn_all.isEnabled()
    widget.deleteLater()


def test_timeout_and_temp_snapshot_cleanup(app, buffer, monkeypatch, tmp_path):
    import hex_editor.analysis_jobs as jobs
    import tempfile
    original = tempfile.TemporaryDirectory
    paths = []
    def directory(**kwargs):
        result = original(dir=tmp_path, **kwargs)
        paths.append(Path(result.name))
        return result
    monkeypatch.setattr(jobs.tempfile, 'TemporaryDirectory', directory)
    buffer.open_bytes(b'a'*500000 + b'!')
    job = AnalysisJob(buffer, dict(kind='regex', pattern='(a+)+$', mode='all'), timeout=.3)
    messages = []
    job.message.connect(messages.append)
    job.launch()
    until(lambda: not _ACTIVE)
    assert any(kind == 'error' and 'time limit' in value for kind, value in messages)
    assert paths and not any(path.exists() for path in paths)


def test_cancel_before_snapshot_and_changed_snapshot(app, buffer, monkeypatch):
    buffer.open_bytes(b'hello'*300000)
    entered, release = threading.Event(), threading.Event()
    original = buffer.read_revision
    def read(*args):
        entered.set()
        assert release.wait(4)
        return original(*args)
    monkeypatch.setattr(buffer, 'read_revision', read)
    widget = StringResultsWidget()
    widget.set_buffer(buffer)
    widget._on_extract()
    until(entered.is_set)
    buffer.write_bytes(0, b'OTHER')
    widget.set_buffer(buffer)
    release.set()
    until(lambda: not _ACTIVE)
    assert not widget._model.rows
    assert widget._controller.job is None
    widget.deleteLater()


def test_high_result_count_is_bounded_and_display_is_virtual(app, buffer):
    from PySide6.QtWidgets import QTableView, QTableWidget
    from hex_editor.analysis_worker import MAX_RESULTS
    buffer.open_bytes(b'abcde\0'*60000)
    widget = StringResultsWidget()
    widget.set_buffer(buffer)
    widget._unicode_cb.setChecked(False)
    widget._on_extract()
    until(lambda: widget._controller.job is None, timeout=20)
    assert len(widget._model.rows) == MAX_RESULTS
    assert 'limit reached' in widget._status.text()
    assert isinstance(widget._table, QTableView) and not isinstance(widget._table, QTableWidget)
    widget.deleteLater()


def test_filter_updates_and_can_be_cancelled(app):
    model = ResultsModel()
    model.append([(i, 5, 'ASCII', 'apple' if i%2 else 'berry') for i in range(50000)])
    model.filter('apple')
    until(lambda: not model._timer.isActive())
    assert model.rowCount() == 25000
    model.filter('berry')
    model.cancel_filter()
    assert model.rowCount() == 25000
    model.filter('nothing')
    until(lambda: not model._timer.isActive())
    assert model.rowCount() == 0


def test_close_window_while_worker_is_stuck_does_not_destroy_running_thread(app, buffer):
    buffer.open_bytes(b'a'*200000 + b'!')
    widget = HexSearchDialog(buffer)
    widget._tabs.setCurrentIndex(2)
    widget._regex_input.setText('(a+)+$')
    widget._find_all()
    until(lambda: widget._controller.job.process is not None)
    start = time.monotonic()
    widget.close()
    widget.deleteLater()
    app.processEvents()
    assert time.monotonic()-start < .15
    until(lambda: not _ACTIVE, timeout=3)


def test_cancelled_format_parse_survives_widget_deletion(app, buffer, monkeypatch):
    import hex_editor.format_viewer as module
    import hex_editor.thread_lifecycle as lifetime
    entered, release = threading.Event(), threading.Event()
    class Parser:
        def __init__(self, _buffer):
            pass
        def parse(self):
            entered.set()
            assert release.wait(4)
            return None
    monkeypatch.setattr(module, 'PeParser', Parser)
    buffer.open_bytes(b'MZ'+b'\0'*64)
    widget = module.FormatViewerWidget()
    widget.set_buffer(buffer)
    until(entered.is_set)
    start = time.monotonic()
    widget.shutdown()
    widget.deleteLater()
    app.processEvents()
    assert time.monotonic()-start < .15
    release.set()
    until(lambda: not lifetime._keeper.threads)


def test_mapped_source_snapshot_never_reads_mmap_in_parent(app, buffer, tmp_path, monkeypatch):
    path = tmp_path/'mapped.bin'
    with path.open('wb') as out:
        out.seek(11*1024*1024)
        out.write(b'needle')
    assert buffer.open_file(str(path))
    def forbidden(*a):
        raise AssertionError('Mapped pages copied inside the GUI process')
    monkeypatch.setattr(buffer, 'read_revision', forbidden)
    widget = HexSearchDialog(buffer)
    widget._tabs.setCurrentIndex(1)
    widget._text_input.setText('needle')
    widget._find_all()
    until(lambda: widget._controller.job is None)
    assert widget._model.rows[0][:2] == (11*1024*1024, 6)
    widget.deleteLater()


def test_changed_mapped_source_is_reported(app, buffer, tmp_path):
    path = tmp_path/'mapped.bin'
    with path.open('wb') as out:
        out.seek(11*1024*1024)
        out.write(b'needle')
    assert buffer.open_file(str(path))
    with path.open('ab') as out:
        out.write(b'changed')
    widget = HexSearchDialog(buffer)
    widget._tabs.setCurrentIndex(1)
    widget._text_input.setText('needle')
    widget._find_all()
    until(lambda: widget._controller.job is None)
    assert 'changed' in widget._status.text()
    assert not widget._model.rows
    widget.deleteLater()


def test_find_next_past_eof_does_not_repeat_empty_match():
    assert not search(b'abc', kind='regex', pattern='$', mode='next', start=4)


def test_worker_memory_limit_is_enforced_in_disposable_process():
    import subprocess
    import sys
    code = '''
from hex_editor.analysis_limits import limit_memory, MEMORY_BUDGET
limit_memory(0)
try:
    impossible = bytearray(MEMORY_BUDGET * 2)
except MemoryError:
    print('bounded')
else:
    raise SystemExit('memory limit was not applied')
'''
    result = subprocess.run([sys.executable, '-c', code], timeout=10, capture_output=True)
    assert result.returncode == 0, result.stderr.decode()
    assert b'bounded' in result.stdout


def test_windows_memory_limit_structure_matches_64_bit_abi():
    import ctypes
    from hex_editor.analysis_limits import _ExtendedLimit
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert ctypes.sizeof(_ExtendedLimit) == 144
