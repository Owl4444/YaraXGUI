"""Revision-gated document state; workers can calculate on immutable snapshots."""
from dataclasses import dataclass
from uuid import uuid4
from .editing import expand_snippet
from .model import Span, TextEdit
from .text import apply_edits


@dataclass(frozen=True)
class Snapshot:
    document: str
    version: int
    generation: int
    text: str
    cursor: int


class Document:
    def __init__(self, text=""):
        self.id = uuid4().hex
        self.text = text
        self.version = 0
        self.cursor = 0
        self.generation = 0
        self.closed = False
        self.diagnostics = ()
        self.completions = ()
        self.tabstops = {}
        self._undo = []
        self._redo = []

    def snapshot(self):
        return Snapshot(self.id, self.version, self.generation, self.text, self.cursor)

    def current(self, snapshot, *, completion=False):
        return (not self.closed and snapshot.document == self.id and snapshot.version == self.version
                and (not completion or (snapshot.generation == self.generation and snapshot.cursor == self.cursor)))

    def dismiss(self):
        self.generation += 1
        self.completions = ()

    def move_cursor(self, offset):
        if not 0 <= offset <= len(self.text):
            raise ValueError("Offset outside document")
        self.cursor = offset
        self.dismiss()

    def edit(self, edits, cursor=None):
        if self.closed:
            raise ValueError("Document is closed")
        result = apply_edits(self.text, edits)
        target_cursor = min(self.cursor, len(result)) if cursor is None else cursor
        if not 0 <= target_cursor <= len(result):
            raise ValueError("Cursor outside edited document")
        self._undo.append((self.text, self.cursor))
        self._redo.clear()
        self.text, self.cursor = result, target_cursor
        self._changed()

    def _changed(self):
        self.version += 1
        self.diagnostics = ()
        self.tabstops = {}
        self.dismiss()

    def undo(self):
        if self._undo and not self.closed:
            self._redo.append((self.text, self.cursor))
            self.text, self.cursor = self._undo.pop()
            self._changed()

    def redo(self):
        if self._redo and not self.closed:
            self._undo.append((self.text, self.cursor))
            self.text, self.cursor = self._redo.pop()
            self._changed()

    def publish_diagnostics(self, snapshot, diagnostics):
        if not self.current(snapshot):
            return False
        self.diagnostics = tuple(diagnostics)
        return True

    def publish_completions(self, snapshot, completions):
        if not self.current(snapshot, completion=True):
            return False
        self.completions = tuple(completions)
        return True

    def accept(self, snapshot, completion):
        if not self.current(snapshot, completion=True):
            return False
        edit = completion.edit
        if completion.snippet:
            snippet = expand_snippet(edit.text)
            edit = TextEdit(edit.span, snippet.text)
            stops = {n: tuple(Span(s.start + edit.span.start, s.end + edit.span.start) for s in spans)
                     for n, spans in snippet.tabstops.items()}
        else:
            stops = {}
        self.edit([edit], edit.span.start + len(edit.text))
        self.tabstops = stops
        if stops:
            number = min((n for n in stops if n), default=0)
            self.cursor = stops[number][0].start
        elif completion.kind == "function" and edit.text.endswith("()"):
            self.cursor -= 1
        return True

    def replace_tabstop(self, number, value):
        """Replace a selected placeholder and all its mirrors as one undo step."""
        spans = self.tabstops.get(number)
        if not spans:
            raise ValueError("Unknown snippet tabstop")
        old = self.tabstops
        edits = [TextEdit(span, value) for span in spans]
        self.edit(edits, spans[0].start + len(value))
        updated = {}
        for key, group in old.items():
            shifted = []
            for span in group:
                delta = sum(len(value) - (s.end - s.start) for s in spans if s.start < span.start)
                start = span.start + delta
                shifted.append(Span(start, start + len(value) if key == number else span.end + delta))
            updated[key] = tuple(shifted)
        self.tabstops = updated

    def close(self):
        self.closed = True
        self.diagnostics = ()
        self.dismiss()

