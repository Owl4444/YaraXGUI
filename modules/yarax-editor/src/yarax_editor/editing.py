"""Pure editing helpers, shared by any future UI adapter."""
from dataclasses import dataclass
import re
from .lexer import noncode_at
from .model import Span, TextEdit


@dataclass(frozen=True)
class ExpandedSnippet:
    text: str
    tabstops: dict[int, tuple[Span, ...]]


def expand_snippet(source):
    """Expand numbered tabstops, defaults, mirrors, choices, and escapes.

    Transformations/environment variables are rejected, never silently pasted.
    """
    pattern = re.compile(r'\\([\\$}])|\$(\d+)|\$\{(\d+)(?::((?:\\.|[^{}])*))?\}|\$\{(\d+)\|([^{}]*)\|\}')
    matches = list(pattern.finditer(source))
    defaults = {}
    for m in matches:
        if m[3] and m[4] is not None:
            defaults[int(m[3])] = re.sub(r'\\([\\$}])', r'\1', m[4])
        elif m[5]:
            defaults[int(m[5])] = m[6].split(",")[0]
    out, stops = [], {}
    previous = length = 0
    for m in matches:
        literal = source[previous:m.start()]
        if re.search(r'\$\{', literal):
            raise ValueError("Unsupported snippet expression")
        out.append(literal)
        length += len(literal)
        if m[1]:
            value = m[1]
        else:
            number = int(m[2] or m[3] or m[5])
            value = defaults.get(number, "")
            stops.setdefault(number, []).append(Span(length, length + len(value)))
        out.append(value)
        length += len(value)
        previous = m.end()
    tail = source[previous:]
    if "${" in tail:
        raise ValueError("Unsupported snippet expression")
    out.append(tail)
    return ExpandedSnippet("".join(out), {n: tuple(v) for n, v in stops.items()})


def newline_edit(text, offset, indent="    "):
    if not 0 <= offset <= len(text):
        raise ValueError("Offset outside document")
    line = text[text.rfind("\n", 0, offset) + 1:offset]
    leading = re.match(r'[ \t]*', line).group()
    previous = text[offset - 1:offset] if offset else ""
    following = text[offset:offset + 1]
    value = "\n" + leading
    cursor = offset + len(value)
    noncode = noncode_at(text, offset)
    if noncode is None:
        if previous in ("{", "(", "["):
            value += indent
            cursor += len(indent)
            if following == {"{": "}", "(": ")", "[": "]"}[previous]:
                value += "\n" + leading
        elif re.fullmatch(r'\s*(meta|strings|condition)\s*:', line):
            value += indent
            cursor += len(indent)
    return TextEdit(Span(offset, offset), value), cursor


def toggle_line_comments(text, selection):
    start = text.rfind("\n", 0, selection.start) + 1
    end_offset = selection.end - 1 if selection.end > selection.start and text[selection.end - 1:selection.end] == "\n" else selection.end
    end = text.find("\n", end_offset)
    end = len(text) if end < 0 else end
    lines = text[start:end].splitlines(keepends=True)
    nonempty = [line for line in lines if line.strip()]
    uncomment = bool(nonempty) and all(line.lstrip().startswith("//") for line in nonempty)
    output = []
    for line in lines:
        leading = len(line) - len(line.lstrip(" \t"))
        if not line.strip():
            output.append(line)
        elif uncomment:
            rest = line[leading + 2:]
            output.append(line[:leading] + (rest[1:] if rest.startswith(" ") else rest))
        else:
            output.append(line[:leading] + "// " + line[leading:])
    return TextEdit(Span(start, end), "".join(output))

