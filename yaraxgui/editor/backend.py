"""Qt scheduling and coordinate adapter for the standalone yarax_editor package."""
from dataclasses import dataclass
from threading import Lock

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot

from yarax_editor import Compiler, CompileOptions, LanguageService, SourceMap, FormatBusy
from yarax_editor.formatting_jobs import MAX_AUTOMATIC_BYTES, MAX_INTERACTIVE_BYTES, check_source_size
from yaraxgui.editor.services import format_runner

_format_slot = Lock()


def analyze_source(text, options):
    result = Compiler(options).validate(text)
    mapping = SourceMap(text)
    diagnostics = []
    for item in result.diagnostics:
        diagnostic = {"message": item.message, "severity": 1 if item.severity == "error" else 2,
                      "code": item.code, "origin": item.origin}
        if item.span is not None:
            diagnostic["range"] = {"start": mapping.position(item.span.start), "end": mapping.position(item.span.end)}
        diagnostics.append(diagnostic)
    # Compiled PyO3 rule objects must stay on this worker thread.
    return {"valid": result.valid, "diagnostics": diagnostics}


@dataclass(frozen=True)
class Reply:
    kind: str
    request_id: int
    state: object
    value: object = None
    error: str = ""


class _Signals(QObject):
    finished = Signal(object)


class _Task(QRunnable):
    def __init__(self, kind, request_id, state, operation):
        super().__init__()
        self.kind, self.request_id, self.state, self.operation = kind, request_id, state, operation
        self.signals = _Signals()

    def run(self):
        try:
            reply = Reply(self.kind, self.request_id, self.state, self.operation())
        except Exception as exc:
            reply = Reply(self.kind, self.request_id, self.state, error=str(exc))
        self.signals.finished.emit(reply)


class EditorBackend(QObject):
    """Coalesce language requests per document; never queue formatting requests."""
    finished = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._counter = 0
        self._active = {}
        self._pending = {}
        self._closed = False

    def request(self, kind, text, state, *, offset=0, explicit=False, options=CompileOptions()):
        if self._closed:
            return -1
        check_source_size(text, MAX_INTERACTIVE_BYTES)
        self._counter += 1
        request_id = self._counter
        if kind == "analyze":
            operation = lambda: analyze_source(text, options)
        elif kind == "complete":
            def operation():
                service = LanguageService(Compiler(options))
                return {"items": service.complete(text, offset, explicit=explicit),
                        "signature": service.signature_help(text, offset),
                        "hover": service.hover(text, max(0, offset - 1))}
        elif kind == "format":
            if kind in self._active:
                return -1
            if not _format_slot.acquire(blocking=False):
                raise FormatBusy("Formatting is already running in another tab")
            def operation():
                try:
                    return format_runner.format(text, compile_options=options)
                finally:
                    _format_slot.release()
        elif kind == "hover":
            operation = lambda: LanguageService(Compiler(options)).hover(text, offset)
        else:
            raise ValueError(f"Unknown editor operation: {kind}")
        task = _Task(kind, request_id, state, operation)
        if kind in self._active:
            self._pending[kind] = task
        else:
            self._start(task)
        return request_id

    def _start(self, task):
        self._active[task.kind] = task
        task.signals.finished.connect(self._done)
        QThreadPool.globalInstance().start(task)

    @Slot(object)
    def _done(self, reply):
        self._active.pop(reply.kind, None)
        if self._closed:
            return
        pending = self._pending.pop(reply.kind, None)
        if pending is not None:
            self._start(pending)
        else:
            self.finished.emit(reply)

    def discard_pending_language(self):
        """Drop obsolete queued work; active replies remain guarded by revisions."""
        for kind in ("analyze", "complete", "hover"):
            self._pending.pop(kind, None)

    def close(self):
        self._closed = True
        self._pending.clear()


def automatic_document_allowed(document):
    # Qt stores UTF-16 units. UTF-8 needs at least as many bytes, so reject
    # large documents without copying/encoding their entire contents per key.
    return (document.characterCount() - 1 <= MAX_AUTOMATIC_BYTES
            and automatic_allowed(document.toPlainText()))


def automatic_allowed(text):
    try:
        check_source_size(text, MAX_AUTOMATIC_BYTES)
        return True
    except ValueError:
        return False
