# -*- coding: utf-8 -*-
"""Selection state model for the hex editor.

Centralises cursor position, drag selection, persistent markers, and
pattern regions into a single source of truth.  The HexWidget, painter,
and clipboard exporter all read from this model instead of maintaining
their own copies.

Design pattern: **Observer** — emits Qt signals when state changes so
that the hex view, data inspector, and status bar stay in sync without
tight coupling.
"""

from PySide6.QtCore import QObject, Signal


class SelectionModel(QObject):
    """Single source of truth for cursor / selection / marker / region state."""

    cursor_moved = Signal(int)            # byte offset
    selection_changed = Signal(int, int)  # (start_offset, length); length=0 clears

    def __init__(self, parent=None):
        super().__init__(parent)
        self._cursor: int = 0
        self._sel_start: int = -1
        self._sel_end: int = -1
        self._selecting: bool = False
        self._focus_ascii: bool = False

        # Persistent green/red markers
        self._marker_start: int = -1
        self._marker_end: int = -1

        # Wildcard pattern builder regions (inclusive pairs)
        self._pattern_regions: list[tuple[int, int]] = []

        # Auto-incrementing YARA pattern counter
        self._yara_counter: int = 0

    # ── Properties ─────────────────────────────────────────────────

    @property
    def cursor(self) -> int:
        return self._cursor

    @property
    def focus_ascii(self) -> bool:
        return self._focus_ascii

    @focus_ascii.setter
    def focus_ascii(self, value: bool):
        self._focus_ascii = value

    @property
    def selecting(self) -> bool:
        return self._selecting

    @selecting.setter
    def selecting(self, value: bool):
        self._selecting = value

    @property
    def marker_start(self) -> int:
        return self._marker_start

    @property
    def marker_end(self) -> int:
        return self._marker_end

    @property
    def pattern_regions(self) -> list[tuple[int, int]]:
        return sorted(self._pattern_regions)

    @property
    def pattern_region_count(self) -> int:
        return len(self._pattern_regions)

    @property
    def yara_counter(self) -> int:
        return self._yara_counter

    def next_yara_id(self) -> int:
        self._yara_counter += 1
        return self._yara_counter

    # ── Cursor ─────────────────────────────────────────────────────

    def set_cursor(self, offset: int, *, emit: bool = True):
        self._cursor = offset
        if emit:
            self.cursor_moved.emit(offset)

    # ── Selection ──────────────────────────────────────────────────

    def ordered_selection(self) -> tuple[int, int]:
        """Return (min, max) of selection range, or (-1, -1)."""
        if self._sel_start < 0 or self._sel_end < 0:
            return (-1, -1)
        return (min(self._sel_start, self._sel_end),
                max(self._sel_start, self._sel_end))

    def has_selection(self) -> bool:
        return self._sel_start >= 0 and self._sel_end >= 0

    def begin_selection(self, offset: int):
        """Start a new selection at *offset* (mouse-press)."""
        self._cursor = offset
        self._sel_start = offset
        self._sel_end = offset
        self._selecting = True
        self.cursor_moved.emit(offset)

    def extend_selection(self, offset: int):
        """Extend selection to *offset* (mouse-drag or Shift+key)."""
        self._sel_end = offset
        self._cursor = offset
        self.cursor_moved.emit(offset)
        self._emit_selection()

    def finish_selection(self):
        """Finalise selection on mouse-release."""
        self._selecting = False
        if self._sel_start == self._sel_end:
            self._sel_start = -1
            self._sel_end = -1
            self.selection_changed.emit(self._cursor, 0)
        else:
            self._emit_selection()

    def shift_extend(self, new_offset: int):
        """Extend selection via Shift+arrow key."""
        if self._sel_start < 0:
            self._sel_start = self._cursor
        self._sel_end = new_offset
        self._cursor = new_offset

    def clear_selection(self):
        self._sel_start = -1
        self._sel_end = -1

    def set_selection(self, start: int, end: int):
        """Directly set the selection range (inclusive)."""
        self._sel_start = start
        self._sel_end = end

    def _emit_selection(self):
        if self._sel_start == self._sel_end:
            self.selection_changed.emit(self._cursor, 0)
        else:
            lo, hi = self.ordered_selection()
            self.selection_changed.emit(lo, hi - lo + 1)

    # ── Markers ────────────────────────────────────────────────────

    def set_marker_start(self):
        self._marker_start = self._cursor
        if self._marker_end >= 0:
            lo = min(self._marker_start, self._marker_end)
            hi = max(self._marker_start, self._marker_end)
            self._sel_start = lo
            self._sel_end = hi

    def set_marker_end(self):
        self._marker_end = self._cursor
        if self._marker_start >= 0:
            lo = min(self._marker_start, self._marker_end)
            hi = max(self._marker_start, self._marker_end)
            self._sel_start = lo
            self._sel_end = hi

    def clear_markers(self):
        self._marker_start = -1
        self._marker_end = -1
        self._sel_start = -1
        self._sel_end = -1

    # ── Pattern regions ────────────────────────────────────────────

    def add_pattern_region(self, lo: int = -1, hi: int = -1):
        """Append a region, merging with overlapping/adjacent ones."""
        if lo < 0 or hi < 0:
            lo, hi = self.active_range()

        new_regions: list[tuple[int, int]] = []
        for rs, re_ in self._pattern_regions:
            if lo <= re_ + 1 and hi >= rs - 1:
                lo = min(lo, rs)
                hi = max(hi, re_)
            else:
                new_regions.append((rs, re_))
        new_regions.append((lo, hi))
        new_regions.sort()
        self._pattern_regions = new_regions
        return len(self._pattern_regions)

    def clear_pattern_regions(self):
        self._pattern_regions.clear()

    # ── Active range (unified source) ──────────────────────────────

    def active_range(self) -> tuple[int, int]:
        """Return (lo, hi) inclusive: markers > selection > cursor."""
        if self._marker_start >= 0 and self._marker_end >= 0:
            return (min(self._marker_start, self._marker_end),
                    max(self._marker_start, self._marker_end))
        if self.has_selection():
            return self.ordered_selection()
        return (self._cursor, self._cursor)

    # ── Clamp to buffer size ───────────────────────────────────────

    def clamp_to_size(self, size: int):
        """Clamp all offsets after a buffer resize (e.g. transform)."""
        max_off = max(0, size - 1)
        if self._cursor > max_off:
            self._cursor = max_off
        if self._sel_start > max_off:
            self._sel_start = -1
        if self._sel_end > max_off:
            self._sel_end = max_off if self._sel_start >= 0 else -1
        if self._marker_start > max_off:
            self._marker_start = -1
        if self._marker_end > max_off:
            self._marker_end = -1

        new_regions: list[tuple[int, int]] = []
        for lo, hi in self._pattern_regions:
            if lo <= max_off:
                new_regions.append((lo, min(hi, max_off)))
        self._pattern_regions = new_regions

    def reset(self):
        """Reset all state (new file loaded)."""
        self._cursor = 0
        self._sel_start = -1
        self._sel_end = -1
        self._selecting = False
        self._marker_start = -1
        self._marker_end = -1
        self._pattern_regions.clear()
