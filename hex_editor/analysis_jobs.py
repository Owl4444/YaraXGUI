"""Off-thread snapshots and child-process supervision; no GUI-thread waits."""
import atexit
import multiprocessing
import tempfile
import threading
import time
from pathlib import Path

from PySide6.QtCore import QThread, Signal
from .analysis_worker import worker_main

_ACTIVE = set()  # Keep QThreads alive until finished, including after a widget closes.
MAX_ACTIVE_JOBS = 2


class AnalysisJob(QThread):
    message = Signal(object)

    def __init__(self, buffer, spec, *, timeout=120):
        super().__init__()
        self.buffer, self.spec = buffer, dict(spec)
        self.revision = buffer.revision
        self.timeout = timeout
        self._cancelled = threading.Event()
        self.process = None

    def launch(self):
        if sum(job.isRunning() for job in _ACTIVE) >= MAX_ACTIVE_JOBS:
            raise ValueError('Two searches are already running; cancel one first')
        _ACTIVE.add(self)
        self.finished.connect(self._release)
        self.start()

    def _release(self):
        _ACTIVE.discard(self)
        self.deleteLater()

    def cancel(self):
        self._cancelled.set()

    def run(self):
        process = None
        receiver = sender = None
        temporary = None
        try:
            temporary = tempfile.TemporaryDirectory(prefix='yaraxgui-analysis-')
            folder = temporary.name
            snapshot = Path(folder) / 'input.bin'
            size = self.buffer.size()
            self.message.emit(('phase', 'Preparing snapshot…'))
            source = self.buffer.analysis_source(self.revision)
            spec = dict(self.spec)
            if source is not None:
                # Page faults in an mmap slice can hold the parent's Python GIL.
                # An unedited mapped file is therefore copied by the child.
                spec['_source_file'] = source
            else:
                with snapshot.open('wb') as stream:
                    for offset in range(0, size, 1024 * 1024):
                        if self._cancelled.is_set():
                            self.message.emit(('done', 'cancelled'))
                            return
                        chunk = self.buffer.read_revision(offset, min(1024 * 1024, size-offset), self.revision)
                        stream.write(chunk)
            if self.buffer.revision != self.revision:
                raise ValueError('File changed during snapshot; run the search again')
            if self._cancelled.is_set():
                self.message.emit(('done', 'cancelled'))
                return
            context = multiprocessing.get_context('spawn')
            receiver, sender = context.Pipe(duplex=False)
            stop = context.Event()
            process = context.Process(target=worker_main,
                args=(sender, str(snapshot), spec, stop), daemon=True)
            self.process = process
            process.start()
            sender.close()
            self.message.emit(('phase', 'Starting analysis…'))
            started = time.monotonic()
            reason = None
            while reason is None:
                if self._cancelled.is_set():
                    reason = 'cancelled'
                    break
                if self.buffer.revision != self.revision:
                    raise ValueError('File changed; search results discarded')
                if time.monotonic() - started > self.timeout:
                    raise TimeoutError(f'Search exceeded the {self.timeout:g}-second time limit; narrow the search')
                if receiver.poll(.02):
                    try:
                        message = receiver.recv()
                    except EOFError:
                        raise RuntimeError('Search worker exited unexpectedly') from None
                    if message[0] == 'error':
                        raise ValueError(message[1])
                    if message[0] == 'done':
                        reason = message[1]
                    else:
                        self.message.emit(message)
                elif not process.is_alive():
                    raise RuntimeError(f'Search worker stopped unexpectedly (exit {process.exitcode})')
            stop.set()
            self.message.emit(('done', reason))
            # Cooperative stop first; a stuck regex is terminated separately.
            process.join(.25)
            if process.is_alive():
                process.terminate()
                process.join(.5)
            if process.is_alive():
                process.kill()
                process.join()
        except Exception as exc:
            self.message.emit(('error', str(exc)))
        finally:
            if process is not None and process.pid is not None:
                if process.is_alive():
                    process.terminate()
                    process.join(.5)
                if process.is_alive():
                    process.kill()
                    process.join()
                process.close()
            if receiver is not None:
                receiver.close()
            if sender is not None:
                sender.close()
            self.process = None
            if temporary is not None:
                try:
                    temporary.cleanup()
                except OSError as exc:
                    self.message.emit(('error', f'Could not remove analysis snapshot: {exc}'))


def shutdown_jobs():
    jobs = list(_ACTIVE)
    for job in jobs:
        job.cancel()
    for job in jobs:
        job.wait()  # Interpreter shutdown only, never a window's close handler.


atexit.register(shutdown_jobs)
