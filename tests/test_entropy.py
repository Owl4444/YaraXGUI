import random

import pytest
import yara_x
from hex_editor.entropy_widget import _EntropyCalcThread, EntropyWidget
from hex_editor.hex_data_buffer import HexDataBuffer
from PySide6.QtTest import QTest


def yara_entropy(data, offset=0, length=None):
    length = len(data) if length is None else length
    rules = yara_x.compile(f'import "math" import "console" rule check {{condition: console.log(math.entropy({offset}, {length}))}}')
    scanner = yara_x.Scanner(rules)
    values = []
    scanner.console_log(values.append)
    scanner.scan(data)
    return float(values[0])


@pytest.mark.parametrize('data', [b'', b'A'*256+b'B'*256, bytes(range(256))*3,
    random.Random(12).randbytes(777)])
def test_file_and_exact_sections_match_yarax_independent_of_block_size(app, data):
    buffer = HexDataBuffer()
    buffer.open_bytes(data)
    ranges = [('file', 0, len(data))]
    if data:
        ranges += [('unaligned', 37, 321), ('overlap', 99, 220),
                   ('clamped', len(data)-5, 100), ('empty', len(data), 0)]
    for block in [64, 256, 8192]:
        worker = _EntropyCalcThread(buffer, block, ranges)
        results = []
        worker.finished_results.connect(results.append)
        worker.run()
        assert len(results) == 1
        assert results[0]['whole'] == pytest.approx(yara_entropy(data), abs=1e-12)
        for name, offset, length in ranges:
            assert results[0]['sections'][(name, offset)] == pytest.approx(yara_entropy(data, offset, length), abs=1e-12)
        if data == b'A'*256+b'B'*256 and block == 256:
            assert results[0]['whole'] == 1
            assert all(value == 0 for _, value in results[0]['blocks'])
    buffer.close()


def test_cancelled_or_changed_entropy_never_publishes_full_file_result(app):
    buffer = HexDataBuffer()
    buffer.open_bytes(b'AB'*300)
    worker = _EntropyCalcThread(buffer, 256)
    results, errors = [], []
    worker.finished_results.connect(results.append)
    worker.failed.connect(errors.append)
    buffer.write_bytes(0, b'C')
    worker.run()
    assert not results and errors
    worker = _EntropyCalcThread(buffer, 256)
    worker.finished_results.connect(results.append)
    worker.cancel()
    worker.run()
    assert not results
    buffer.close()


def test_entropy_ui_displays_whole_file_value(app):
    buffer = HexDataBuffer()
    buffer.open_bytes(b'A'*256+b'B'*256)
    widget = EntropyWidget()
    widget.set_buffer(buffer)
    widget._on_calculate()
    for _ in range(500):
        if widget._thread is None:
            break
        QTest.qWait(10)
    assert widget._avg_label.text() == 'File entropy: 1.000000'
    assert widget._graph._section_entropy[('File', 0)] == 1
    widget.shutdown()
    widget.deleteLater()
    buffer.close()
