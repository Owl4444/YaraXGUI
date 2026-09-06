from bisect import bisect_left, bisect_right
from .model import Span, TextEdit


class SourceMap:
    """Strict conversions among Python offsets, UTF-8 spans, and LSP UTF-16."""
    def __init__(self, text):
        self.text = text
        self.lines = [0] + [i + 1 for i, ch in enumerate(text) if ch == "\n"]
        self.utf8 = [0]
        self.utf16 = [0]
        for ch in text:
            self.utf8.append(self.utf8[-1] + len(ch.encode("utf-8")))
            self.utf16.append(self.utf16[-1] + (2 if ord(ch) > 0xffff else 1))

    def position(self, offset):
        if not 0 <= offset <= len(self.text):
            raise ValueError("Offset outside document")
        line = bisect_right(self.lines, offset) - 1
        return {"line": line, "character": self.utf16[offset] - self.utf16[self.lines[line]]}

    def offset(self, line, character):
        if not 0 <= line < len(self.lines) or character < 0:
            raise ValueError("Position outside document")
        start = self.lines[line]
        end = self.lines[line + 1] - 1 if line + 1 < len(self.lines) else len(self.text)
        if end > start and self.text[end - 1:end] == "\r":
            end -= 1
        target = self.utf16[start] + character
        index = bisect_left(self.utf16, target, start, end + 1)
        if index > end or self.utf16[index] != target:
            raise ValueError("Position splits a surrogate pair or exceeds line")
        return index

    def byte_offset(self, offset):
        index = bisect_left(self.utf8, offset)
        if index >= len(self.utf8) or self.utf8[index] != offset:
            raise ValueError("Invalid UTF-8 boundary")
        return index

    def byte_span(self, start, end):
        return Span(self.byte_offset(start), self.byte_offset(end))


def apply_edits(text: str, edits: list[TextEdit]) -> str:
    edits = sorted(edits, key=lambda e: (e.span.start, e.span.end))
    previous = 0
    parts = []
    for edit in edits:
        if not previous <= edit.span.start <= edit.span.end <= len(text):
            raise ValueError("Overlapping or out-of-range edits")
        parts.extend((text[previous:edit.span.start], edit.text))
        previous = edit.span.end
    parts.append(text[previous:])
    return "".join(parts)

