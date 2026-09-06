"""Lossless, tolerant editor lexer based on the pinned upstream tokenizer.

It never validates semantics. Unknown/incomplete input remains editable. Every
character belongs to exactly one token, including whitespace and comments.
"""
from dataclasses import dataclass
from functools import lru_cache
import re
from .model import Span


@dataclass(frozen=True)
class Token:
    kind: str
    span: Span
    text: str
    closed: bool = True


WORD = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
REFERENCE = re.compile(r"[$#@!][A-Za-z_0-9]*")
NUMBER = re.compile(r"(?:0x[0-9a-fA-F][0-9a-fA-F_]*|0o[0-7][0-7_]*|[0-9][0-9_]*\.[0-9_]+|[0-9][0-9_]*(?:KB|MB)?)")
TRIVIA = {"whitespace", "comment"}
LITERALS = {"string", "multiline_string", "regex", "hex"}


@lru_cache(maxsize=8)
def tokenize(text: str) -> tuple[Token, ...]:
    tokens = []
    i = 0
    pending_hex = False
    while i < len(text):
        start = i
        closed = True
        if text[i].isspace():
            i += 1
            while i < len(text) and text[i].isspace():
                i += 1
            kind = "whitespace"
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            if i > start and text[i - 1:i] == "\r":
                i -= 1
            kind, closed = "comment", end >= 0
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = len(text) if end < 0 else end + 2
            kind, closed = "comment", end >= 0
        elif text[i] in '\"/':
            delimiter = '"""' if text.startswith('"""', i) else text[i]
            kind = "multiline_string" if len(delimiter) == 3 else "string" if delimiter == '"' else "regex"
            i += len(delimiter)
            closed = False
            while i < len(text):
                if text[i] == "\\":
                    i = min(i + 2, len(text))
                elif text.startswith(delimiter, i):
                    i += len(delimiter)
                    closed = True
                    break
                else:
                    i += 1
            if kind == "regex" and closed:
                for _ in range(2):
                    if i < len(text) and text[i].isascii() and text[i].isalpha():
                        i += 1
            pending_hex = False
        elif text[i] == "{" and pending_hex:
            kind = "hex"
            i += 1
            closed = False
            while i < len(text):
                if text.startswith("//", i):
                    end = text.find("\n", i)
                    i = len(text) if end < 0 else end + 1
                elif text.startswith("/*", i):
                    end = text.find("*/", i + 2)
                    i = len(text) if end < 0 else end + 2
                elif text[i] == "}":
                    i += 1
                    closed = True
                    break
                else:
                    i += 1
            pending_hex = False
        else:
            pending_hex = False
            if text.startswith(("==", "!=", ">=", "<=", "<<", ">>"), i):
                kind, i = "operator", i + 2
            else:
                match = WORD.match(text, i)
                kind = "identifier"
                if not match:
                    match, kind = NUMBER.match(text, i), "number"
                if not match:
                    match, kind = REFERENCE.match(text, i), "reference"
                if match:
                    i = match.end()
                else:
                    kind = "punctuation" if text[i] in "{}[]():,." else "operator" if text[i] in "=+-*\\%&|^~<>" else "unknown"
                    pending_hex = text[i] == "="
                    i += 1
        tokens.append(Token(kind, Span(start, i), text[start:i], closed))
    return tuple(tokens)


def significant(text):
    return tuple(token for token in tokenize(text) if token.kind not in TRIVIA)


def comment_spans(text):
    """Include comments embedded in hex patterns without inspecting strings/regex."""
    for token in tokenize(text):
        if token.kind == "comment":
            yield token.span
        elif token.kind == "hex":
            for match in re.finditer(r'//[^\r\n]*|/\*[\s\S]*?(?:\*/|$)', token.text):
                yield Span(token.span.start + match.start(), token.span.start + match.end())


def noncode_at(text, offset):
    """A position at a closed token's end is back in code."""
    if not 0 <= offset <= len(text):
        raise ValueError("Offset outside document")
    for token in tokenize(text):
        if token.span.start >= offset:
            break
        if token.kind in LITERALS | {"comment"}:
            if offset < token.span.end or (offset == token.span.end and
                    (not token.closed or (token.kind == "comment" and token.text.startswith("//")))):
                return token
    return None
