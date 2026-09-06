"""Project-owned, lossless-token formatter; no yaraast or upstream formatter.

Literal and comment contents remain byte-for-byte intact. Formatting changes
only the whitespace between tokens. Both sides are checked by YARA-X.
"""
from dataclasses import dataclass
from .compiler import Compiler
from .lexer import tokenize


class FormatError(ValueError):
    def __init__(self, message, diagnostics=()):
        super().__init__(message)
        self.diagnostics = diagnostics


@dataclass(frozen=True)
class FormatOptions:
    indent: str = "    "
    newline: str = "\n"

    def __post_init__(self):
        if not self.indent or any(c not in " \t" for c in self.indent):
            raise ValueError("Indent must contain spaces or tabs")
        if self.newline not in ("\n", "\r\n"):
            raise ValueError("Newline must be LF or CRLF")


def token_identity(text):
    return tuple((t.kind, t.text) for t in tokenize(text) if t.kind != "whitespace")


def format_source(text, *, compiler=None, options=FormatOptions()):
    compiler = compiler or Compiler()
    before = compiler.validate(text)
    if not before.valid:
        raise FormatError("Cannot format invalid source", before.diagnostics)
    tokens = [t for t in tokenize(text) if t.kind != "whitespace"]
    out = []
    indent = 0
    rule_depth = 0
    section = None
    at_line_start = True
    previous = ""
    pending_section = False
    parens = 0

    def newline():
        nonlocal at_line_start
        if not at_line_start:
            out.append(options.newline)
            at_line_start = True

    def emit(value, space=True):
        nonlocal at_line_start
        if at_line_start:
            out.append(options.indent * max(0, indent))
        elif space:
            out.append(" ")
        out.append(value)
        at_line_start = value.endswith("\n")

    for i, token in enumerate(tokens):
        value = token.text
        following = tokens[i + 1].text if i + 1 < len(tokens) else ""
        is_section = rule_depth == 1 and value in ("meta", "strings", "condition") and following == ":"
        is_assignment = section in ("meta", "strings") and token.kind in ("identifier", "reference") and following == "="
        # Preserve line-comment and warning-suppression attachment. Original
        # newlines also remain boundaries (blank lines are normalized).
        gap = text[tokens[i - 1].span.end:token.span.start] if i else ""
        if "\n" in gap:
            newline()
        if at_line_start and section == "condition":
            indent = 2 + max(0, parens - (1 if value in (")", "]") else 0))
        if is_section:
            newline()
            indent = 1
            section, pending_section = value, True
        elif is_assignment:
            newline()
        if value == "}" and token.kind == "punctuation":
            newline()
            indent = 0
            rule_depth = 0
            section = None
        if value in ("rule", "private", "global", "import", "include") and not rule_depth and previous not in ("private", "global"):
            newline()
        # Spacing is intentionally conservative; no arithmetic/boolean rewrite.
        tight = value in (".", ",", ":", ")", "]") or previous in (".", "(", "[")
        emit(value, space=not tight)
        if value == "{" and token.kind == "punctuation":
            rule_depth = 1
            indent = 1
            newline()
        elif value == ":" and pending_section:
            pending_section = False
            indent = 2
            newline()
        elif value == "}" and token.kind == "punctuation":
            newline()
        elif token.kind == "comment" and value.startswith("//"):
            newline()
        if token.kind == "punctuation" and section == "condition":
            if value in ("(", "["):
                parens += 1
            elif value in (")", "]"):
                parens = max(0, parens - 1)
        if value == "}":
            parens = 0
        previous = value
    newline()
    result = "".join(out)
    if token_identity(text) != token_identity(result):
        raise FormatError("Formatting would change tokens; original source retained")
    after = compiler.validate(result)
    if not after.valid:
        raise FormatError("Formatted source failed compiler validation", after.diagnostics)
    # Warning suppression is semantic too: retain the original text if moving
    # a directive could change the warning set.
    identity = lambda d: (d.severity, d.code, d.message)
    if sorted(map(identity, before.diagnostics)) != sorted(map(identity, after.diagnostics)):
        raise FormatError("Formatting would change diagnostics; original source retained")
    return result
