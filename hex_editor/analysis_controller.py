"""Shared GUI lifecycle for search/extraction: revisions, cancellation and status."""
from PySide6.QtCore import QObject, Signal
from .analysis_jobs import AnalysisJob


class AnalysisController(QObject):
    changed = Signal(bool)
    status = Signal(str)
    progress = Signal(int)

    def __init__(self, model, parent):
        super().__init__(parent)
        self.model = model
        self.job = None
        self.buffer = None
        self._cancelled = False
        self._outcome = ''

    def set_buffer(self, buffer):
        self.close()
        self.buffer = buffer
        self.model.clear()
        self.status.emit('')

    def start(self, spec):
        if self.job is not None:
            return
        if self.buffer is None or not self.buffer.size():
            self.status.emit('Open a nonempty file first')
            return
        from yaraxgui.recovery.widgets import flush_drafts
        flush_drafts()
        self.model.clear()
        job = AnalysisJob(self.buffer, spec)
        self.job = job
        self._cancelled = False
        self._outcome = ''
        job.message.connect(self._message)
        job.finished.connect(self._finished)
        self.parent().destroyed.connect(job.cancel)
        self.changed.emit(True)
        self.status.emit('Preparing snapshot…')
        try:
            job.launch()
        except Exception as exc:
            self.job = None
            job.deleteLater()
            self.changed.emit(False)
            self.status.emit(str(exc))

    def cancel(self):
        self.model.cancel_filter()
        if self.job is not None:
            self._cancelled = True
            self.job.cancel()
            self.status.emit('Cancelling…')

    def close(self):
        self.cancel()
        self._cancelled = True
        self.job = None  # The global supervisor retains it until safely finished.
        self.changed.emit(False)

    def _message(self, message):
        if self.sender() is not self.job or self._cancelled:
            return
        if self.buffer.revision != self.job.revision:
            self.cancel()
            self.model.clear()
            return
        kind, value = message
        if kind == 'batch':
            self.model.append(value)
            self.status.emit(f'{len(self.model.rows):,} results so far…')
        elif kind == 'progress':
            self.progress.emit(value)
        elif kind == 'phase':
            self.status.emit(value)
        elif kind == 'error':
            self._outcome = f'Error: {value}'
        elif kind == 'done':
            self._outcome = f'{len(self.model.rows):,} results — {value}'

    def _finished(self):
        if self.sender() is not self.job:
            return
        self.job = None
        self.changed.emit(False)
        self.status.emit(f'Cancelled — {len(self.model.rows):,} partial results retained'
                         if self._cancelled else self._outcome or 'Search finished')
