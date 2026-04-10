# -*- coding: utf-8 -*-
"""Byte editing controller for the hex editor.

Handles in-place hex/ASCII typing, insert/delete, undo/redo, paste,
fill, and NOP — matching Binja / IDA / 010Editor / ImHex hotkeys.

Design pattern: **Command** — every edit is an undoable EditCommand
stored on a stack.  The controller owns the undo/redo stacks and
delegates buffer mutations to HexDataBuffer.

Hotkey reference (shown in status bar):
    Hex digits (0-F)   Overwrite nibble at cursor
    Printable ASCII    Overwrite byte in ASCII column
    Ins                Toggle overwrite / insert mode
    Delete             Delete byte(s) at cursor or selection
    Backspace          Delete byte before cursor
    Ctrl+Z             Undo
    Ctrl+Shift+Z       Redo
    Ctrl+V             Paste (hex or ASCII depending on column)
    Ctrl+I             Insert N bytes at cursor
    Ctrl+Shift+F       Fill selection with byte pattern
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .hex_data_buffer import HexDataBuffer


# ── Edit commands (undo/redo units) ────────────────────────────────


@dataclass
class EditCommand:
    """One undoable edit operation.

    Adjacent single-byte edits of the same kind are coalesced into one
    command by extending ``old_bytes`` / ``new_bytes`` and updating
    ``cursor_after``.  This keeps the undo stack (and the edit log
    table) compact — 1000 consecutive overwrites become 1 row instead
    of 1000.
    """
    description: str
    offset: int
    old_bytes: bytes       # what was there before
    new_bytes: bytes       # what we wrote (may differ in length)
    cursor_before: int     # cursor position before the edit
    cursor_after: int      # cursor position after the edit
    size_changed: bool = False  # True if insert/delete changed buffer size
    _coalesce_key: str = ""  # non-empty → eligible for coalescing with same key


class EditController:
    """Manages byte edits with undo/redo stacks.

    The controller does NOT own the buffer — it's passed in.  After
    each edit, the caller must refresh the UI (call
    ``hex_widget.refresh_after_data_change()``).
    """

    MAX_UNDO = 500

    def __init__(self):
        self._buffer: HexDataBuffer | None = None
        self._undo_stack: list[EditCommand] = []
        self._redo_stack: list[EditCommand] = []
        self._insert_mode: bool = False  # False = overwrite (default)
        # Nibble entry state
        self._pending_nibble: int | None = None
        self._pending_nibble_offset: int = -1
        # Dirty-byte tracking: maps byte offset -> original value.
        # Only the *first* original value is kept per offset so we
        # can always show what changed relative to the file on disk.
        self._dirty_offsets: dict[int, int] = {}
        # Set of offsets currently modified (value differs from original).
        # Rebuilt after every edit/undo/redo for paint queries.
        self._modified_offsets: set[int] = set()

    @property
    def insert_mode(self) -> bool:
        return self._insert_mode

    def toggle_insert_mode(self) -> bool:
        self._insert_mode = not self._insert_mode
        self._clear_nibble()
        return self._insert_mode

    def set_buffer(self, buf: HexDataBuffer | None):
        self._buffer = buf
        self._undo_stack.clear()
        self._redo_stack.clear()
        self._clear_nibble()
        self._dirty_offsets.clear()
        self._modified_offsets.clear()

    @property
    def modified_offsets(self) -> set[int]:
        """Set of byte offsets whose current value differs from original."""
        return self._modified_offsets

    @property
    def dirty_offsets(self) -> dict[int, int]:
        """Map of byte offset -> original value (before any edits)."""
        return self._dirty_offsets

    @property
    def edit_history(self) -> list[EditCommand]:
        """Read-only view of the undo stack (oldest first)."""
        return list(self._undo_stack)

    def has_undo(self) -> bool:
        return len(self._undo_stack) > 0

    def has_redo(self) -> bool:
        return len(self._redo_stack) > 0

    def is_offset_modified(self, offset: int) -> bool:
        """Fast check used by the painter for per-byte coloring."""
        return offset in self._modified_offsets

    # ── Dirty tracking helpers ─────────────────────────────────────

    def _record_originals(self, offset: int, length: int):
        """Snapshot original byte values before an overwrite edit.

        Only records the *first* original value per offset so that
        chained edits (e.g. typing two nibbles) don't overwrite the
        baseline.
        """
        if not self._buffer or length <= 0:
            return
        data = self._buffer.read(offset, length)
        for i, b in enumerate(data):
            off = offset + i
            if off not in self._dirty_offsets:
                self._dirty_offsets[off] = b

    def _record_originals_for_insert(self, offset: int):
        """For insert ops, shift existing dirty entries at >= offset."""
        # Entries at >= offset shift right by the inserted length.
        # We don't do this for every single insert (costly), but we
        # rebuild _modified_offsets from scratch after every edit
        # which is the source of truth for painting.
        pass

    def _rebuild_modified(self):
        """Rebuild _modified_offsets by comparing dirty_offsets against
        the current buffer contents."""
        self._modified_offsets.clear()
        if not self._buffer:
            return
        for off, orig_val in self._dirty_offsets.items():
            if off < self._buffer.size():
                cur = self._buffer.read(off, 1)
                if cur and cur[0] != orig_val:
                    self._modified_offsets.add(off)
            # Offsets beyond buffer size (deleted bytes) are not shown

    # ── Nibble state ───────────────────────────────────────────────

    def _clear_nibble(self):
        self._pending_nibble = None
        self._pending_nibble_offset = -1

    # ── Core edit operations ───────────────────────────────────────

    def overwrite_byte(self, offset: int, value: int) -> EditCommand | None:
        """Overwrite a single byte at *offset*."""
        if not self._buffer or offset < 0 or offset >= self._buffer.size():
            return None
        self._record_originals(offset, 1)
        old = self._buffer.read(offset, 1)
        new = bytes([value & 0xFF])
        if old == new:
            return None
        self._buffer.write_bytes(offset, new)
        cmd = EditCommand(
            description=f"Overwrite 0x{offset:X}: {old[0]:02X} -> {value:02X}",
            offset=offset, old_bytes=old, new_bytes=new,
            cursor_before=offset, cursor_after=offset + 1,
            _coalesce_key="overwrite")
        self._push_undo(cmd)
        return cmd

    def type_hex_nibble(self, offset: int, nibble: int) -> EditCommand | None:
        """Handle one hex digit keystroke (nibble-by-nibble entry).

        First digit sets the high nibble (cursor stays). Second digit
        sets the low nibble and advances the cursor.  If insert mode
        is on, the first nibble inserts a new 0x?0 byte instead.
        """
        if not self._buffer or offset < 0:
            return None

        if self._insert_mode:
            # In insert mode, each nibble pair inserts a new byte
            if self._pending_nibble is not None and self._pending_nibble_offset == offset:
                # Second nibble — complete the byte
                value = (self._pending_nibble << 4) | (nibble & 0x0F)
                # The byte was already inserted with high nibble; overwrite it
                self._buffer.write_bytes(offset, bytes([value]))
                # Amend the last undo entry
                if self._undo_stack:
                    self._undo_stack[-1].new_bytes = bytes([value])
                    self._undo_stack[-1].cursor_after = offset + 1
                    self._undo_stack[-1].description = f"Insert 0x{offset:X}: {value:02X}"
                self._clear_nibble()
                return self._undo_stack[-1] if self._undo_stack else None
            else:
                # First nibble — insert a new byte with high nibble set
                self._clear_nibble()
                value = (nibble & 0x0F) << 4
                old = b""
                new = bytes([value])
                self._buffer.replace_range(offset, offset - 1, new)
                cmd = EditCommand(
                    description=f"Insert 0x{offset:X}: {value:02X}...",
                    offset=offset, old_bytes=old, new_bytes=new,
                    cursor_before=offset, cursor_after=offset,
                    size_changed=True, _coalesce_key="insert")
                self._push_undo(cmd)
                self._pending_nibble = nibble & 0x0F
                self._pending_nibble_offset = offset
                return cmd
        else:
            # Overwrite mode — nibble entry on existing byte
            if offset >= self._buffer.size():
                return None
            if self._pending_nibble is not None and self._pending_nibble_offset == offset:
                # Second nibble — complete the byte (originals already recorded)
                value = (self._pending_nibble << 4) | (nibble & 0x0F)
                self._buffer.write_bytes(offset, bytes([value]))
                if self._undo_stack:
                    self._undo_stack[-1].new_bytes = bytes([value])
                    self._undo_stack[-1].cursor_after = offset + 1
                    self._undo_stack[-1].description = f"Overwrite 0x{offset:X}: {self._undo_stack[-1].old_bytes[0]:02X} -> {value:02X}"
                self._clear_nibble()
                self._rebuild_modified()
                return self._undo_stack[-1] if self._undo_stack else None
            else:
                # First nibble — write high nibble, keep low nibble from old byte
                self._clear_nibble()
                self._record_originals(offset, 1)
                old = self._buffer.read(offset, 1)
                if not old:
                    return None
                value = ((nibble & 0x0F) << 4) | (old[0] & 0x0F)
                self._buffer.write_bytes(offset, bytes([value]))
                cmd = EditCommand(
                    description=f"Overwrite 0x{offset:X}: {old[0]:02X} -> ...",
                    offset=offset, old_bytes=old, new_bytes=bytes([value]),
                    cursor_before=offset, cursor_after=offset,
                    _coalesce_key="overwrite")
                self._push_undo(cmd)
                self._pending_nibble = nibble & 0x0F
                self._pending_nibble_offset = offset
                return cmd

    def type_ascii_char(self, offset: int, char: str) -> EditCommand | None:
        """Type a printable ASCII character in the ASCII column."""
        if not self._buffer or offset < 0:
            return None
        self._clear_nibble()
        value = ord(char) & 0xFF

        if not self._insert_mode and offset < self._buffer.size():
            self._record_originals(offset, 1)

        if self._insert_mode:
            old = b""
            new = bytes([value])
            self._buffer.replace_range(offset, offset - 1, new)
            cmd = EditCommand(
                description=f"Insert ASCII 0x{offset:X}: '{char}'",
                offset=offset, old_bytes=old, new_bytes=new,
                cursor_before=offset, cursor_after=offset + 1,
                size_changed=True, _coalesce_key="insert")
            self._push_undo(cmd)
            return cmd
        else:
            if offset >= self._buffer.size():
                return None
            return self.overwrite_byte(offset, value)

    def delete_at(self, offset: int, count: int = 1) -> EditCommand | None:
        """Delete *count* bytes starting at *offset*."""
        if not self._buffer or offset < 0 or offset >= self._buffer.size():
            return None
        self._clear_nibble()
        count = min(count, self._buffer.size() - offset)
        if count > 0:
            self._record_originals(offset, count)
        if count <= 0:
            return None
        old = self._buffer.read(offset, count)
        self._buffer.replace_range(offset, offset + count - 1, b"")
        cmd = EditCommand(
            description=f"Delete {count} byte(s) at 0x{offset:X}",
            offset=offset, old_bytes=old, new_bytes=b"",
            cursor_before=offset, cursor_after=min(offset, max(0, self._buffer.size() - 1)),
            size_changed=True)
        self._push_undo(cmd)
        return cmd

    def delete_selection(self, lo: int, hi: int) -> EditCommand | None:
        """Delete the inclusive byte range [lo, hi]."""
        return self.delete_at(lo, hi - lo + 1)

    def backspace(self, offset: int) -> EditCommand | None:
        """Delete the byte before *offset* (like pressing Backspace)."""
        if offset <= 0:
            return None
        return self.delete_at(offset - 1, 1)

    def insert_bytes(self, offset: int, data: bytes) -> EditCommand | None:
        """Insert *data* at *offset* (shifts everything after)."""
        if not self._buffer or offset < 0 or not data:
            return None
        self._clear_nibble()
        offset = min(offset, self._buffer.size())
        self._buffer.replace_range(offset, offset - 1, data)
        cmd = EditCommand(
            description=f"Insert {len(data)} byte(s) at 0x{offset:X}",
            offset=offset, old_bytes=b"", new_bytes=data,
            cursor_before=offset, cursor_after=offset + len(data),
            size_changed=True)
        self._push_undo(cmd)
        return cmd

    def fill_range(self, lo: int, hi: int, pattern: bytes) -> EditCommand | None:
        """Fill the inclusive range [lo, hi] with repeating *pattern*."""
        if not self._buffer or lo < 0 or hi < lo or not pattern:
            return None
        self._clear_nibble()
        hi = min(hi, self._buffer.size() - 1)
        length = hi - lo + 1
        self._record_originals(lo, length)
        old = self._buffer.read(lo, length)
        # Build the fill data by repeating the pattern
        fill = (pattern * ((length // len(pattern)) + 1))[:length]
        self._buffer.write_bytes(lo, fill)
        cmd = EditCommand(
            description=f"Fill 0x{lo:X}-0x{hi:X} with {pattern.hex().upper()}",
            offset=lo, old_bytes=old, new_bytes=fill,
            cursor_before=lo, cursor_after=hi + 1)
        self._push_undo(cmd)
        return cmd

    def paste_overwrite(self, offset: int, data: bytes) -> EditCommand | None:
        """Paste by overwriting bytes at *offset*."""
        if not self._buffer or offset < 0 or not data:
            return None
        self._clear_nibble()
        end = min(offset + len(data), self._buffer.size())
        actual_len = end - offset
        if actual_len <= 0:
            return None
        self._record_originals(offset, actual_len)
        old = self._buffer.read(offset, actual_len)
        self._buffer.write_bytes(offset, data[:actual_len])
        cmd = EditCommand(
            description=f"Paste overwrite {actual_len} byte(s) at 0x{offset:X}",
            offset=offset, old_bytes=old, new_bytes=data[:actual_len],
            cursor_before=offset, cursor_after=offset + actual_len)
        self._push_undo(cmd)
        return cmd

    def paste_insert(self, offset: int, data: bytes) -> EditCommand | None:
        """Paste by inserting bytes at *offset*."""
        return self.insert_bytes(offset, data)

    # ── Undo / Redo ────────────────────────────────────────────────

    def undo(self) -> EditCommand | None:
        """Undo the last edit. Returns the command (for cursor restore)."""
        if not self._undo_stack or not self._buffer:
            return None
        self._clear_nibble()
        cmd = self._undo_stack.pop()
        # Reverse the edit
        if cmd.size_changed:
            if len(cmd.new_bytes) == 0:
                # Was a delete — re-insert the old bytes
                self._buffer.replace_range(cmd.offset, cmd.offset - 1, cmd.old_bytes)
            elif len(cmd.old_bytes) == 0:
                # Was an insert — delete the inserted bytes
                end = cmd.offset + len(cmd.new_bytes) - 1
                self._buffer.replace_range(cmd.offset, end, b"")
            else:
                # Was a size-changing replace
                end = cmd.offset + len(cmd.new_bytes) - 1
                self._buffer.replace_range(cmd.offset, end, cmd.old_bytes)
        else:
            # Simple overwrite — restore old bytes
            self._buffer.write_bytes(cmd.offset, cmd.old_bytes)
        self._redo_stack.append(cmd)
        self._rebuild_modified()
        return cmd

    def redo(self) -> EditCommand | None:
        """Redo the last undone edit."""
        if not self._redo_stack or not self._buffer:
            return None
        self._clear_nibble()
        cmd = self._redo_stack.pop()
        # Re-apply the edit
        if cmd.size_changed:
            if len(cmd.new_bytes) == 0:
                end = cmd.offset + len(cmd.old_bytes) - 1
                self._buffer.replace_range(cmd.offset, end, b"")
            elif len(cmd.old_bytes) == 0:
                self._buffer.replace_range(cmd.offset, cmd.offset - 1, cmd.new_bytes)
            else:
                end = cmd.offset + len(cmd.old_bytes) - 1
                self._buffer.replace_range(cmd.offset, end, cmd.new_bytes)
        else:
            self._buffer.write_bytes(cmd.offset, cmd.new_bytes)
        self._undo_stack.append(cmd)
        self._rebuild_modified()
        return cmd

    def _push_undo(self, cmd: EditCommand):
        """Push a command, coalescing with the previous if adjacent and same type."""
        if (cmd._coalesce_key
                and self._undo_stack
                and self._undo_stack[-1]._coalesce_key == cmd._coalesce_key):
            prev = self._undo_stack[-1]
            # Adjacent: new edit starts right where the previous ended
            if cmd.offset == prev.offset + len(prev.new_bytes):
                prev.old_bytes = prev.old_bytes + cmd.old_bytes
                prev.new_bytes = prev.new_bytes + cmd.new_bytes
                prev.cursor_after = cmd.cursor_after
                n = len(prev.new_bytes)
                if prev.size_changed:
                    prev.description = (
                        f"Insert {n} byte(s) at 0x{prev.offset:X}")
                else:
                    prev.description = (
                        f"Overwrite {n} byte(s) at "
                        f"0x{prev.offset:X}\u20130x{prev.offset + n - 1:X}")
                self._redo_stack.clear()
                self._rebuild_modified()
                return
            # Prepend: new edit is right before the previous start
            # (happens with leftward typing, rare but handle it)
            if cmd.offset + len(cmd.new_bytes) == prev.offset:
                prev.old_bytes = cmd.old_bytes + prev.old_bytes
                prev.new_bytes = cmd.new_bytes + prev.new_bytes
                prev.offset = cmd.offset
                prev.cursor_before = cmd.cursor_before
                n = len(prev.new_bytes)
                if prev.size_changed:
                    prev.description = (
                        f"Insert {n} byte(s) at 0x{prev.offset:X}")
                else:
                    prev.description = (
                        f"Overwrite {n} byte(s) at "
                        f"0x{prev.offset:X}\u20130x{prev.offset + n - 1:X}")
                self._redo_stack.clear()
                self._rebuild_modified()
                return

        self._undo_stack.append(cmd)
        if len(self._undo_stack) > self.MAX_UNDO:
            self._undo_stack.pop(0)
        self._redo_stack.clear()
        self._rebuild_modified()
