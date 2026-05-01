# -*- coding: utf-8 -*-
"""Clipboard export and YARA pattern generation for the hex editor.

Consolidates the 8+ repetitive copy methods that all followed the same
get-bytes -> format -> clipboard pattern into a registry of named
formatters.

Design pattern: **Registry / Strategy** — each export format is a
callable registered by name.  Adding a new format is a one-liner.
"""

from __future__ import annotations

import base64
from typing import Callable

from PySide6.QtWidgets import QApplication

from .hex_data_buffer import HexDataBuffer
from .selection_model import SelectionModel


# Type alias for a formatter: bytes -> str
Formatter = Callable[[bytes], str]


# ── Format registry ────────────────────────────────────────────────

_FORMATS: dict[str, Formatter] = {}


def register_format(name: str, fn: Formatter):
    _FORMATS[name] = fn


def _fmt_hex(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)

def _fmt_hex_compact(data: bytes) -> str:
    return "".join(f"{b:02X}" for b in data)

def _fmt_yara_hex(data: bytes) -> str:
    return "{ " + " ".join(f"{b:02X}" for b in data) + " }"

def _fmt_c_escape(data: bytes) -> str:
    return "".join(f"\\x{b:02X}" for b in data)

def _fmt_python_bytes(data: bytes) -> str:
    return "b'" + "".join(f"\\x{b:02x}" for b in data) + "'"

def _fmt_ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)

def _fmt_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def _fmt_hex_to_text(data: bytes) -> str:
    parts: list[str] = []
    for b in data:
        if 32 <= b <= 126:
            parts.append(chr(b))
        elif b == 0x0a:
            parts.append("\\n")
        elif b == 0x0d:
            parts.append("\\r")
        elif b == 0x09:
            parts.append("\\t")
        elif b == 0x00:
            parts.append("\\0")
        else:
            parts.append(f"\\x{b:02x}")
    return "".join(parts)

def _fmt_text_to_hex(data: bytes) -> str:
    return " ".join(f"0x{b:02X}" for b in data)


# Register all built-in formats
register_format("hex", _fmt_hex)
register_format("hex_compact", _fmt_hex_compact)
register_format("yara_hex", _fmt_yara_hex)
register_format("c_escape", _fmt_c_escape)
register_format("python_bytes", _fmt_python_bytes)
register_format("ascii", _fmt_ascii)
register_format("base64", _fmt_base64)
register_format("hex_to_text", _fmt_hex_to_text)
register_format("text_to_hex", _fmt_text_to_hex)


# ── Exporter ───────────────────────────────────────────────────────


class ClipboardExporter:
    """Handles all copy-to-clipboard and YARA pattern generation.

    Reads active bytes from the SelectionModel + HexDataBuffer,
    formats with the requested formatter, and pushes to the system
    clipboard.
    """

    def __init__(self, buffer: HexDataBuffer | None,
                 selection: SelectionModel):
        self._buffer = buffer
        self._selection = selection

    def set_buffer(self, buf: HexDataBuffer | None):
        self._buffer = buf

    def active_bytes(self) -> bytes:
        """Return bytes from: markers range > drag selection > cursor byte."""
        if not self._buffer:
            return b""
        sel = self._selection
        if sel.marker_start >= 0 and sel.marker_end >= 0:
            lo = min(sel.marker_start, sel.marker_end)
            hi = max(sel.marker_start, sel.marker_end)
            return self._buffer.read(lo, hi - lo + 1)
        if sel.has_selection():
            lo, hi = sel.ordered_selection()
            return self._buffer.read(lo, hi - lo + 1)
        return self._buffer.read(sel.cursor, 1)

    def copy(self, format_name: str) -> bool:
        """Copy active bytes to clipboard in the named format.

        Returns True if bytes were copied.
        """
        data = self.active_bytes()
        if not data:
            return False
        formatter = _FORMATS.get(format_name)
        if formatter is None:
            return False
        QApplication.clipboard().setText(formatter(data))
        return True

    def copy_smart(self, focus_ascii: bool):
        """Copy as ASCII if focus is on ASCII column, else as hex."""
        data = self.active_bytes()
        if not data:
            return
        if focus_ascii:
            QApplication.clipboard().setText(_fmt_ascii(data))
        else:
            QApplication.clipboard().setText(_fmt_hex(data))

    # ── YARA pattern generation ────────────────────────────────────

    def generate_yara_pattern(self) -> str:
        """Generate ``$hex_N = { ... }  // offset, size``."""
        data = self.active_bytes()
        if not data:
            return ""
        sel = self._selection
        counter = sel.next_yara_id()
        hex_str = _fmt_hex(data)
        lo, _ = sel.active_range()
        return (f"$hex_{counter} = {{ {hex_str} }}"
                f"  // 0x{lo:08X}, {len(data)} bytes")

    def generate_yara_ascii(self) -> str:
        """Generate ``$str_N = "..." [ascii|wide]  // offset, size``."""
        data = self.active_bytes()
        if not data:
            return ""
        sel = self._selection
        counter = sel.next_yara_id()
        lo, _ = sel.active_range()
        # Escape YARA string special chars
        text = ""
        for b in data:
            if b == 0x00:
                text += "\\0"
            elif b == 0x09:
                text += "\\t"
            elif b == 0x0A:
                text += "\\n"
            elif b == 0x0D:
                text += "\\r"
            elif b == 0x22:
                text += '\\"'
            elif b == 0x5C:
                text += "\\\\"
            elif 0x20 <= b < 0x7F:
                text += chr(b)
            else:
                text += f"\\x{b:02x}"
        return (f'$str_{counter} = "{text}" ascii'
                f"  // 0x{lo:08X}, {len(data)} bytes")

    def generate_yara_regex(self) -> str:
        """Generate ``$re_N = /.../ [ascii|wide]  // offset, size``."""
        data = self.active_bytes()
        if not data:
            return ""
        sel = self._selection
        counter = sel.next_yara_id()
        lo, _ = sel.active_range()
        # Build regex: printable chars as literal (escaped if regex-special),
        # non-printable as \xNN
        _REGEX_META = set(r"\.^$*+?{}[]|()")
        text = ""
        for b in data:
            ch = chr(b) if 0x20 <= b < 0x7F else ""
            if ch and ch in _REGEX_META:
                text += "\\" + ch
            elif ch:
                text += ch
            elif b == 0x09:
                text += "\\t"
            elif b == 0x0A:
                text += "\\n"
            elif b == 0x0D:
                text += "\\r"
            else:
                text += f"\\x{b:02x}"
        return (f"$re_{counter} = /{text}/"
                f"  // 0x{lo:08X}, {len(data)} bytes")

    def build_wildcard_pattern(self) -> str:
        """Generate a YARA hex pattern with [N] wildcards between regions."""
        if not self._buffer:
            return ""
        regions = self._selection.pattern_regions
        if not regions:
            return ""
        parts: list[str] = []
        for i, (start, end) in enumerate(regions):
            data = self._buffer.read(start, end - start + 1)
            hex_bytes = _fmt_hex(data)
            if i > 0:
                prev_end = regions[i - 1][1]
                gap = start - (prev_end + 1)
                if gap > 0:
                    parts.append(f"[{gap}]")
            parts.append(hex_bytes)

        counter = self._selection.next_yara_id()
        origin = regions[0][0]
        return (f"$wildcard_{counter} = {{ {' '.join(parts)} }}"
                f"  // {len(regions)} regions from 0x{origin:08X}")

    def generate_all_region_patterns(self) -> str:
        """Generate a separate $hex_N for each pattern region."""
        if not self._buffer:
            return ""
        regions = self._selection.pattern_regions
        if not regions:
            return ""
        lines: list[str] = []
        for start, end in regions:
            data = self._buffer.read(start, end - start + 1)
            hex_str = _fmt_hex(data)
            counter = self._selection.next_yara_id()
            lines.append(
                f"$hex_{counter} = {{ {hex_str} }}"
                f"  // 0x{start:08X}, {len(data)} bytes"
            )
        return "\n    ".join(lines)
