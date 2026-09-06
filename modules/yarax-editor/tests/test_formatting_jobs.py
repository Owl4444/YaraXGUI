import multiprocessing
import os
import threading
import time
from types import SimpleNamespace

import pytest

from yarax_editor import CompileOptions, FormatError, FormatRunner, FormatBusy, FormatTimeout, SourceTooLarge
from yarax_editor import formatting_jobs
from yarax_editor.formatting_jobs import check_source_size

SOURCE = 'rule r {condition: with n = filesize : (n > 0)}'


def stalled_worker(*args):
    time.sleep(60)


def crashed_worker(*args):
    os._exit(1)


def test_worker_formats_with_external_globals_and_preserves_diagnostics():
    runner = FormatRunner(interval=0)
    result = runner.format('rule r {condition: limit > 0}', compile_options=CompileOptions(globals={'limit': 3}))
    assert '\n    condition:\n' in result
    with pytest.raises(FormatError) as error:
        runner.format('rule r {condition: missing}')
    assert error.value.diagnostics[0].span is not None
    assert 'missing' in error.value.diagnostics[0].message
    assert runner.format(SOURCE).endswith('\n')


def test_thousands_of_rules_fit_interactive_budget():
    source = '\n'.join(f'rule r_{n} {{condition: filesize > {n}}}' for n in range(2000))
    assert len(source) > 64 * 1024
    result = FormatRunner().format(source)
    assert result.count('condition:') == 2000


def test_size_boundary_is_utf8_and_rejected_before_worker_creation(monkeypatch):
    check_source_size('😀' * 1024, 4096)
    with pytest.raises(SourceTooLarge):
        check_source_size('😀' * 1024 + 'a', 4096)
    runner = FormatRunner(max_bytes=4096)
    monkeypatch.setattr(runner._context, 'Process', lambda **kwargs: pytest.fail('Oversized source launched a worker'))
    with pytest.raises(SourceTooLarge):
        runner.format('a' * 4097)


def test_cooldown_rejects_without_queue_then_recovers(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(formatting_jobs, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    runner = FormatRunner(interval=1)
    assert runner.format(SOURCE)
    with pytest.raises(FormatBusy, match='wait a moment'):
        runner.format(SOURCE)
    clock[0] += 1
    assert runner.format(SOURCE)


def test_timeout_kills_worker_releases_slot_and_rejects_concurrent_jobs(monkeypatch):
    original_worker = formatting_jobs._format_worker
    existing = {p.pid for p in multiprocessing.active_children()}
    monkeypatch.setattr(formatting_jobs, '_format_worker', stalled_worker)
    runner = FormatRunner(timeout=0.5, interval=0)
    errors = []

    def run():
        try:
            runner.format(SOURCE)
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=run)
    start = time.monotonic()
    thread.start()
    deadline = start + 3
    while not runner._lock.locked() and time.monotonic() < deadline:
        time.sleep(0.005)
    with pytest.raises(FormatBusy, match='already running'):
        runner.format(SOURCE)
    thread.join(timeout=4)
    assert not thread.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], FormatTimeout)
    assert time.monotonic() - start < 4
    assert {p.pid for p in multiprocessing.active_children()} <= existing
    monkeypatch.setattr(formatting_jobs, '_format_worker', original_worker)
    runner.timeout = 5
    assert runner.format(SOURCE)


def test_crashed_worker_does_not_hold_slot(monkeypatch):
    runner = FormatRunner(interval=0)
    monkeypatch.setattr(formatting_jobs, '_format_worker', crashed_worker)
    with pytest.raises(FormatError, match='worker stopped'):
        runner.format(SOURCE)
    assert not runner._lock.locked()
