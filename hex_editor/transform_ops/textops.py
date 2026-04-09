# -*- coding: utf-8 -*-
"""Text operations: replace (literal/regex), regex search, case change."""

from __future__ import annotations

import re

from ..transforms import TransformError, TransformParam, register_transform


# ── helpers ─────────────────────────────────────────────────────────

_FLAG_MAP = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "ASCII": re.ASCII,
}


def _build_flags(flag_csv: str) -> int:
    flags = 0
    for token in (flag_csv or "").split(","):
        token = token.strip().upper()
        if not token:
            continue
        if token not in _FLAG_MAP:
            raise TransformError(f"Unknown regex flag: {token}")
        flags |= _FLAG_MAP[token]
    return flags


def _decode(data: bytes, encoding: str) -> str:
    try:
        return data.decode(encoding, errors="replace")
    except LookupError as e:
        raise TransformError(f"Unknown encoding: {encoding}") from e


def _encode(text: str, encoding: str) -> bytes:
    try:
        return text.encode(encoding, errors="replace")
    except LookupError as e:
        raise TransformError(f"Unknown encoding: {encoding}") from e


# ── replace (literal or regex) ─────────────────────────────────────

@register_transform(
    name="Replace",
    category="Text",
    params=[
        TransformParam("mode", "Mode", "choice",
                       choices=["literal", "regex"],
                       default="literal",
                       help="'literal' = byte-for-byte replace. "
                            "'regex' = Python re.sub (supports \\1, \\g<name>)."),
        TransformParam("find", "Find", "text",
                       placeholder="needle   or   \\b\\w+\\b"),
        TransformParam("replace", "Replace", "text",
                       placeholder="replacement   or   \\g<0>"),
        TransformParam("flags", "Regex flags", "text",
                       placeholder="IGNORECASE, MULTILINE",
                       help="Regex mode only. Comma-separated: "
                            "IGNORECASE, MULTILINE, DOTALL, ASCII."),
        TransformParam("encoding", "Encoding", "choice",
                       choices=["utf-8", "latin-1", "ascii", "utf-16-le"],
                       default="utf-8"),
        TransformParam("count", "Max replacements (0 = all)", "int",
                       default="0"),
    ],
    help=("Find-and-replace over the selection. Choose 'literal' for a "
          "byte-for-byte replace, or 'regex' for Python re.sub."),
)
def replace_op(data: bytes, params: dict) -> bytes:
    mode = (params.get("mode") or "literal").strip().lower()
    find = params.get("find", "")
    if not find:
        raise TransformError("Find field is empty.")
    enc = params.get("encoding", "utf-8")
    count = int(params.get("count", 0) or 0)
    repl = params.get("replace", "")

    if mode == "regex":
        flags = _build_flags(params.get("flags", ""))
        text = _decode(data, enc)
        try:
            result = re.sub(find, repl, text,
                            count=max(count, 0), flags=flags)
        except re.error as e:
            raise TransformError(f"Bad regex: {e}") from e
        return _encode(result, enc)

    # literal
    needle = _encode(find, enc)
    repl_bytes = _encode(repl, enc)
    # bytes.replace: count=-1 means all; 0 means zero replacements.
    return data.replace(needle, repl_bytes, -1 if count <= 0 else count)


# ── regex search / extract ─────────────────────────────────────────

@register_transform(
    name="Search (regex)",
    category="Text",
    params=[
        TransformParam("pattern", "Pattern", "text",
                       placeholder=r"(?P<ip>\d+\.\d+\.\d+\.\d+)"),
        TransformParam("mode", "Output", "choice",
                       choices=["list matches", "list group", "first match",
                                "count", "offsets"],
                       default="list matches"),
        TransformParam("group", "Group (name or index)", "text",
                       default="0",
                       help="Used when Output = 'list group'."),
        TransformParam("flags", "Flags", "text",
                       placeholder="IGNORECASE, MULTILINE",
                       help="Comma-separated: IGNORECASE, MULTILINE, DOTALL, ASCII."),
        TransformParam("encoding", "Encoding", "choice",
                       choices=["utf-8", "latin-1", "ascii", "utf-16-le"],
                       default="utf-8"),
        TransformParam("separator", "Separator", "text",
                       default=r"\n",
                       help=r"Output separator. \n and \t are interpreted."),
    ],
    help="Regex search. Replaces the region with the selected output.",
)
def search_regex(data: bytes, params: dict) -> bytes:
    pattern = params.get("pattern", "")
    if not pattern:
        raise TransformError("Pattern is empty.")
    enc = params.get("encoding", "utf-8")
    flags = _build_flags(params.get("flags", ""))
    mode = params.get("mode", "list matches")
    sep = (params.get("separator", r"\n")
           .replace(r"\n", "\n").replace(r"\t", "\t").replace(r"\r", "\r"))
    text = _decode(data, enc)
    try:
        compiled = re.compile(pattern, flags=flags)
    except re.error as e:
        raise TransformError(f"Bad regex: {e}") from e

    if mode == "first match":
        m = compiled.search(text)
        return _encode(m.group(0) if m else "", enc)

    if mode == "count":
        return _encode(str(len(compiled.findall(text))), enc)

    if mode == "offsets":
        parts = [f"{m.start()}-{m.end()}: {m.group(0)}"
                 for m in compiled.finditer(text)]
        return _encode(sep.join(parts), enc)

    if mode == "list group":
        g_raw = (params.get("group") or "0").strip()
        try:
            g: int | str = int(g_raw)
        except ValueError:
            g = g_raw
        try:
            parts = [m.group(g) or "" for m in compiled.finditer(text)]
        except IndexError as e:
            raise TransformError(f"No such group: {g}") from e
        return _encode(sep.join(parts), enc)

    # default: list matches
    parts = [m.group(0) for m in compiled.finditer(text)]
    return _encode(sep.join(parts), enc)


# ── case conversion ────────────────────────────────────────────────

@register_transform(
    name="To upper/lower",
    category="Text",
    params=[
        TransformParam("case", "Case", "choice",
                       choices=["upper", "lower", "swap", "title"],
                       default="upper"),
        TransformParam("encoding", "Encoding", "choice",
                       choices=["utf-8", "latin-1", "ascii"],
                       default="utf-8"),
    ],
    length_preserving=True,
)
def change_case(data: bytes, params: dict) -> bytes:
    enc = params.get("encoding", "utf-8")
    text = _decode(data, enc)
    case = params.get("case", "upper")
    out = {"upper": text.upper, "lower": text.lower,
           "swap": text.swapcase, "title": text.title}.get(case, text.upper)()
    return _encode(out, enc)
