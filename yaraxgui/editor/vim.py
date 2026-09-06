# -*- coding: utf-8 -*-
"""
VimHandler - Self-contained vim-style keybinding handler for QTextEdit.

Provides Normal, Insert, Visual, Visual Line, and Command modes with
common vim motions, operations, and search.
"""

from enum import Enum, auto

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtGui import QKeyEvent, QTextCursor
from PySide6.QtWidgets import QTextEdit


class VimMode(Enum):
    NORMAL = auto()
    INSERT = auto()
    VISUAL = auto()
    VISUAL_LINE = auto()
    COMMAND = auto()


_MODE_DISPLAY = {
    VimMode.NORMAL: "-- NORMAL --",
    VimMode.INSERT: "-- INSERT --",
    VimMode.VISUAL: "-- VISUAL --",
    VimMode.VISUAL_LINE: "-- V-LINE --",
    VimMode.COMMAND: "",
}


class VimHandler(QObject):
    """Vim-style key handling for a QTextEdit widget."""

    mode_changed = Signal(str)  # emits display string like "-- NORMAL --"
    save_requested = Signal()
    quit_requested = Signal()

    def __init__(self, editor: QTextEdit, parent=None):
        super().__init__(parent)
        self._editor = editor
        self._enabled = False
        self._mode = VimMode.NORMAL

        # State
        self._count_buffer = ""
        self._operator_pending = ""  # 'd', 'c', 'y'
        self._g_prefix = False
        self._register = ""
        self._yank_buffer = ""
        self._yank_is_linewise = False

        # Search
        self._search_pattern = ""
        self._search_forward = True
        self._command_buffer = ""

        # Visual
        self._visual_anchor = 0

        # Insert-mode mappings (imap): {key_sequence: action_callable}
        # e.g. {"jk": lambda: self._imap_escape()}
        self._imaps = {}
        self._imap_buffer = ""
        self._imap_timer = QTimer(self)
        self._imap_timer.setSingleShot(True)
        self._imap_timer.setInterval(200)  # ms timeout for sequence
        self._imap_timer.timeout.connect(self._imap_timeout)
        self._imap_pending_event = None  # stash the first event for flushing

        self._imap_flushing = False  # reentrance guard for flush

        # Default mapping: jk -> Escape
        self.imap("jk", self._imap_escape)

    # ─── Public API ───────────────────────────────────────────────────

    def enable(self):
        self._enabled = True
        self._set_mode(VimMode.NORMAL)
        self._editor.setCursorWidth(8)

    def disable(self):
        self._enabled = False
        self._editor.setCursorWidth(2)
        self._imap_cancel_pending()
        self._clear_state()
        self.mode_changed.emit("")

    def is_enabled(self) -> bool:
        return self._enabled

    def imap(self, keys: str, action):
        """Register an insert-mode key mapping.

        Args:
            keys: Character sequence (e.g. "jk").
            action: Callable to invoke when the sequence is typed.
        """
        self._imaps[keys] = action

    def iunmap(self, keys: str):
        """Remove an insert-mode key mapping."""
        self._imaps.pop(keys, None)

    def handle_key_event(self, event) -> bool:
        """Process a key event. Returns True if consumed."""
        if not self._enabled:
            return False

        if self._mode == VimMode.INSERT:
            return self._handle_insert_key(event)
        elif self._mode == VimMode.COMMAND:
            return self._handle_command_key(event)
        elif self._mode in (VimMode.VISUAL, VimMode.VISUAL_LINE):
            return self._handle_visual_key(event)
        else:
            return self._handle_normal_key(event)

    # ─── Mode management ─────────────────────────────────────────────

    def _set_mode(self, mode: VimMode):
        self._mode = mode
        if mode == VimMode.NORMAL:
            self._editor.setCursorWidth(8)
            # Clear any selection
            tc = self._editor.textCursor()
            tc.clearSelection()
            self._editor.setTextCursor(tc)
        elif mode == VimMode.INSERT:
            self._editor.setCursorWidth(2)
        self._clear_state()
        self.mode_changed.emit(_MODE_DISPLAY.get(mode, ""))

    def _clear_state(self):
        self._count_buffer = ""
        self._operator_pending = ""
        self._g_prefix = False

    def _get_count(self, default=1):
        return int(self._count_buffer) if self._count_buffer else default

    # ─── INSERT mode ─────────────────────────────────────────────────

    def _handle_insert_key(self, event) -> bool:
        if event.key() == Qt.Key.Key_Escape:
            self._imap_cancel_pending()
            self._imap_escape()
            return True

        # If we're flushing buffered chars, skip imap detection entirely
        if self._imap_flushing:
            return False

        text = event.text()

        # --- imap sequence detection ---
        if text and self._imaps:
            candidate = self._imap_buffer + text

            # Check for exact match
            if candidate in self._imaps:
                self._imap_timer.stop()
                action = self._imaps[candidate]
                self._imap_buffer = ""
                self._imap_pending_event = None
                action()
                return True

            # Check if candidate is a prefix of any mapping
            is_prefix = any(m.startswith(candidate) and len(m) > len(candidate)
                           for m in self._imaps)
            if is_prefix:
                if not self._imap_buffer:
                    # First char of potential sequence - stash the event
                    self._imap_pending_event = event.clone()
                self._imap_buffer = candidate
                self._imap_timer.start()
                return True

            # Not a prefix and not a match - flush any pending chars
            if self._imap_buffer:
                self._imap_flush_and_forward(event)
                return True

        # Let everything else pass through to QTextEdit
        return False

    def _imap_escape(self):
        """Escape to normal mode (used as default jk mapping target)."""
        tc = self._editor.textCursor()
        if tc.positionInBlock() > 0:
            tc.movePosition(QTextCursor.MoveOperation.Left)
            self._editor.setTextCursor(tc)
        self._set_mode(VimMode.NORMAL)

    def _imap_timeout(self):
        """Timer expired - the user didn't complete the sequence, flush buffered chars."""
        if self._imap_buffer:
            buf = self._imap_buffer
            self._imap_buffer = ""
            self._imap_pending_event = None
            self._imap_flushing = True
            try:
                for ch in buf:
                    fake = QKeyEvent(QKeyEvent.Type.KeyPress, 0, Qt.KeyboardModifier.NoModifier, ch)
                    self._editor.keyPressEvent(fake)
            finally:
                self._imap_flushing = False

    def _imap_flush_and_forward(self, current_event):
        """Flush pending buffer chars then forward the current event."""
        self._imap_timer.stop()
        buf = self._imap_buffer
        self._imap_buffer = ""
        self._imap_pending_event = None
        self._imap_flushing = True
        try:
            for ch in buf:
                fake = QKeyEvent(QKeyEvent.Type.KeyPress, 0, Qt.KeyboardModifier.NoModifier, ch)
                self._editor.keyPressEvent(fake)
            self._editor.keyPressEvent(current_event)
        finally:
            self._imap_flushing = False

    def _imap_cancel_pending(self):
        """Cancel any pending imap sequence without flushing."""
        self._imap_timer.stop()
        self._imap_buffer = ""
        self._imap_pending_event = None

    # ─── NORMAL mode ─────────────────────────────────────────────────

    def _handle_normal_key(self, event) -> bool:
        key = event.key()
        mod = event.modifiers()
        text = event.text()

        # Ctrl combos pass through (except Ctrl+R for redo)
        if mod & Qt.KeyboardModifier.ControlModifier:
            if key == Qt.Key.Key_R:
                self._editor.document().redo()
                return True
            return False  # let Ctrl+S, Ctrl+W etc. pass through

        # Count prefix
        if text.isdigit() and (self._count_buffer or text != '0'):
            self._count_buffer += text
            return True

        # g prefix
        if text == 'g' and not self._g_prefix and not self._operator_pending:
            self._g_prefix = True
            return True

        if self._g_prefix:
            return self._handle_g_command(text)

        # Operator pending
        if self._operator_pending:
            return self._handle_operator_motion(text, key)

        # --- Motions ---
        if text == 'h':
            self._move_cursor(QTextCursor.MoveOperation.Left, self._get_count())
            return True
        if text == 'l':
            self._move_cursor(QTextCursor.MoveOperation.Right, self._get_count())
            return True
        if text == 'j':
            self._move_cursor(QTextCursor.MoveOperation.Down, self._get_count())
            return True
        if text == 'k':
            self._move_cursor(QTextCursor.MoveOperation.Up, self._get_count())
            return True

        if text == 'w':
            self._move_cursor(QTextCursor.MoveOperation.NextWord, self._get_count())
            return True
        if text == 'W':
            self._move_word_WORD(forward=True, count=self._get_count())
            return True
        if text == 'b':
            self._move_cursor(QTextCursor.MoveOperation.PreviousWord, self._get_count())
            return True
        if text == 'B':
            self._move_word_WORD(forward=False, count=self._get_count())
            return True
        if text == 'e':
            self._move_end_of_word(count=self._get_count())
            return True
        if text == 'E':
            self._move_end_of_WORD(count=self._get_count())
            return True

        if text == '0':
            self._move_cursor(QTextCursor.MoveOperation.StartOfBlock)
            return True
        if text == '$':
            self._move_cursor(QTextCursor.MoveOperation.EndOfBlock)
            return True
        if text == '^':
            self._move_first_non_blank()
            return True

        if text == 'G':
            count = self._get_count(default=0)
            if count > 0 or self._count_buffer:
                self._goto_line(count)
            else:
                self._move_cursor(QTextCursor.MoveOperation.End)
            self._clear_state()
            return True

        if text == '{':
            self._move_paragraph(forward=False, count=self._get_count())
            return True
        if text == '}':
            self._move_paragraph(forward=True, count=self._get_count())
            return True

        # --- Insert entry ---
        if text == 'i':
            self._set_mode(VimMode.INSERT)
            return True
        if text == 'I':
            self._move_first_non_blank()
            self._set_mode(VimMode.INSERT)
            return True
        if text == 'a':
            tc = self._editor.textCursor()
            if not tc.atBlockEnd():
                tc.movePosition(QTextCursor.MoveOperation.Right)
                self._editor.setTextCursor(tc)
            self._set_mode(VimMode.INSERT)
            return True
        if text == 'A':
            self._move_cursor(QTextCursor.MoveOperation.EndOfBlock)
            self._set_mode(VimMode.INSERT)
            return True
        if text == 'o':
            self._move_cursor(QTextCursor.MoveOperation.EndOfBlock)
            tc = self._editor.textCursor()
            tc.insertText("\n")
            self._editor.setTextCursor(tc)
            self._set_mode(VimMode.INSERT)
            return True
        if text == 'O':
            self._move_cursor(QTextCursor.MoveOperation.StartOfBlock)
            tc = self._editor.textCursor()
            tc.insertText("\n")
            tc.movePosition(QTextCursor.MoveOperation.Up)
            self._editor.setTextCursor(tc)
            self._set_mode(VimMode.INSERT)
            return True

        # --- Operations ---
        if text == 'x':
            self._delete_chars(self._get_count())
            self._clear_state()
            return True
        if text == 'X':
            self._delete_chars_before(self._get_count())
            self._clear_state()
            return True

        if text in ('d', 'c', 'y'):
            self._operator_pending = text
            return True

        if text == 'p':
            self._paste(after=True)
            self._clear_state()
            return True
        if text == 'P':
            self._paste(after=False)
            self._clear_state()
            return True

        if text == 'u':
            self._editor.document().undo()
            self._clear_state()
            return True

        if text == 'J':
            self._join_lines(self._get_count())
            self._clear_state()
            return True

        if text == '~':
            self._toggle_case(self._get_count())
            self._clear_state()
            return True

        # --- Visual mode ---
        if text == 'v':
            self._enter_visual(VimMode.VISUAL)
            return True
        if text == 'V':
            self._enter_visual(VimMode.VISUAL_LINE)
            return True

        # --- Search ---
        if text == '/':
            self._search_forward = True
            self._command_buffer = "/"
            self._set_mode_raw(VimMode.COMMAND)
            return True
        if text == '?':
            self._search_forward = False
            self._command_buffer = "?"
            self._set_mode_raw(VimMode.COMMAND)
            return True
        if text == 'n':
            self._search_next(forward=self._search_forward)
            return True
        if text == 'N':
            self._search_next(forward=not self._search_forward)
            return True

        # --- Command mode ---
        if text == ':':
            self._command_buffer = ":"
            self._set_mode_raw(VimMode.COMMAND)
            return True

        # Consume unrecognized keys in normal mode to prevent phantom typing
        self._clear_state()
        return True

    # ─── g-prefix commands ───────────────────────────────────────────

    def _handle_g_command(self, text):
        if text == 'g':  # gg - go to top
            count = self._get_count(default=1)
            self._goto_line(count)
            self._clear_state()
            self._g_prefix = False
            return True
        # Unknown g command, clear
        self._g_prefix = False
        self._clear_state()
        return True

    # ─── Operator + motion ───────────────────────────────────────────

    def _handle_operator_motion(self, text, key):
        op = self._operator_pending
        count = self._get_count()

        # Double operator: dd, yy, cc - operate on whole lines
        if text == op:
            if op == 'd':
                self._delete_lines(count)
            elif op == 'y':
                self._yank_lines(count)
            elif op == 'c':
                self._change_lines(count)
            self._clear_state()
            return True

        # Count inside operator (e.g., d3w)
        if text.isdigit():
            self._count_buffer += text
            return True

        # Operator + motion
        tc = self._editor.textCursor()
        start_pos = tc.position()

        moved = self._execute_motion(text, key, count, select=True)
        if not moved:
            self._clear_state()
            return True

        tc = self._editor.textCursor()
        if tc.hasSelection():
            selected = tc.selectedText()
            if op == 'd':
                self._yank_buffer = selected
                self._yank_is_linewise = False
                tc.removeSelectedText()
            elif op == 'y':
                self._yank_buffer = selected
                self._yank_is_linewise = False
                tc.clearSelection()
                tc.setPosition(start_pos)
            elif op == 'c':
                self._yank_buffer = selected
                self._yank_is_linewise = False
                tc.removeSelectedText()
                self._editor.setTextCursor(tc)
                self._set_mode(VimMode.INSERT)
                return True
            self._editor.setTextCursor(tc)

        self._clear_state()
        return True

    def _execute_motion(self, text, key, count, select=False):
        """Execute a motion, optionally selecting text. Returns True if motion recognized."""
        mode = QTextCursor.MoveMode.KeepAnchor if select else QTextCursor.MoveMode.MoveAnchor

        motions = {
            'h': QTextCursor.MoveOperation.Left,
            'l': QTextCursor.MoveOperation.Right,
            'j': QTextCursor.MoveOperation.Down,
            'k': QTextCursor.MoveOperation.Up,
            'w': QTextCursor.MoveOperation.NextWord,
            'b': QTextCursor.MoveOperation.PreviousWord,
            '0': QTextCursor.MoveOperation.StartOfBlock,
            '$': QTextCursor.MoveOperation.EndOfBlock,
        }

        if text in motions:
            tc = self._editor.textCursor()
            for _ in range(count):
                tc.movePosition(motions[text], mode)
            self._editor.setTextCursor(tc)
            return True

        if text == 'e':
            tc = self._editor.textCursor()
            for _ in range(count):
                tc.movePosition(QTextCursor.MoveOperation.NextWord, mode)
                tc.movePosition(QTextCursor.MoveOperation.Right, mode)  # include last char
            self._editor.setTextCursor(tc)
            return True

        if text == 'G':
            tc = self._editor.textCursor()
            tc.movePosition(QTextCursor.MoveOperation.End, mode)
            self._editor.setTextCursor(tc)
            return True

        if text == '^':
            tc = self._editor.textCursor()
            tc.movePosition(QTextCursor.MoveOperation.StartOfBlock, mode)
            # Move to first non-blank
            block_text = tc.block().text()
            indent = len(block_text) - len(block_text.lstrip())
            for _ in range(indent):
                tc.movePosition(QTextCursor.MoveOperation.Right, mode)
            self._editor.setTextCursor(tc)
            return True

        return False

    # ─── VISUAL mode ─────────────────────────────────────────────────

    def _enter_visual(self, mode: VimMode):
        tc = self._editor.textCursor()
        self._visual_anchor = tc.position()
        if mode == VimMode.VISUAL_LINE:
            tc.movePosition(QTextCursor.MoveOperation.StartOfBlock)
            self._visual_anchor = tc.position()
            tc.movePosition(QTextCursor.MoveOperation.EndOfBlock, QTextCursor.MoveMode.KeepAnchor)
        self._editor.setTextCursor(tc)
        self._mode = mode
        self._clear_state()
        self.mode_changed.emit(_MODE_DISPLAY[mode])

    def _handle_visual_key(self, event) -> bool:
        key = event.key()
        mod = event.modifiers()
        text = event.text()

        if mod & Qt.KeyboardModifier.ControlModifier:
            return False

        if key == Qt.Key.Key_Escape:
            self._set_mode(VimMode.NORMAL)
            return True

        # Motions extend selection
        count = self._get_count()
        if text.isdigit() and (self._count_buffer or text != '0'):
            self._count_buffer += text
            return True

        motion_keys = {'h', 'j', 'k', 'l', 'w', 'b', 'e', '0', '$', '^', 'G', '{', '}'}
        if text in motion_keys:
            self._visual_move(text, count)
            return True

        # g prefix in visual
        if text == 'g':
            self._g_prefix = True
            return True
        if self._g_prefix and text == 'g':
            self._g_prefix = False
            tc = self._editor.textCursor()
            tc.setPosition(self._visual_anchor)
            tc.movePosition(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.KeepAnchor)
            self._editor.setTextCursor(tc)
            self._clear_state()
            return True

        # Operations on selection
        if text in ('d', 'x'):
            self._operate_visual('d')
            return True
        if text == 'y':
            self._operate_visual('y')
            return True
        if text == 'c':
            self._operate_visual('c')
            return True

        self._clear_state()
        return True

    def _visual_move(self, text, count):
        tc = self._editor.textCursor()
        mode = QTextCursor.MoveMode.KeepAnchor

        motions = {
            'h': QTextCursor.MoveOperation.Left,
            'l': QTextCursor.MoveOperation.Right,
            'j': QTextCursor.MoveOperation.Down,
            'k': QTextCursor.MoveOperation.Up,
            'w': QTextCursor.MoveOperation.NextWord,
            'b': QTextCursor.MoveOperation.PreviousWord,
            '0': QTextCursor.MoveOperation.StartOfBlock,
            '$': QTextCursor.MoveOperation.EndOfBlock,
        }

        if text in motions:
            # Re-establish anchor
            tc.setPosition(self._visual_anchor)
            current = self._editor.textCursor().position()
            if text in motions:
                # Calculate new position
                temp = self._editor.textCursor()
                for _ in range(count):
                    temp.movePosition(motions[text], QTextCursor.MoveMode.MoveAnchor)
                new_pos = temp.position()
                tc.setPosition(self._visual_anchor)
                tc.setPosition(new_pos, QTextCursor.MoveMode.KeepAnchor)
            self._editor.setTextCursor(tc)
            return

        if text == '^':
            tc.setPosition(self._visual_anchor)
            tc.movePosition(QTextCursor.MoveOperation.StartOfBlock, mode)
            block_text = tc.block().text()
            indent = len(block_text) - len(block_text.lstrip())
            for _ in range(indent):
                tc.movePosition(QTextCursor.MoveOperation.Right, mode)
            self._editor.setTextCursor(tc)
            return

        if text == 'G':
            tc.setPosition(self._visual_anchor)
            tc.movePosition(QTextCursor.MoveOperation.End, mode)
            self._editor.setTextCursor(tc)
            return

        if text == '{':
            current = self._editor.textCursor()
            for _ in range(count):
                self._move_paragraph_cursor(current, forward=False)
            tc.setPosition(self._visual_anchor)
            tc.setPosition(current.position(), QTextCursor.MoveMode.KeepAnchor)
            self._editor.setTextCursor(tc)
            return

        if text == '}':
            current = self._editor.textCursor()
            for _ in range(count):
                self._move_paragraph_cursor(current, forward=True)
            tc.setPosition(self._visual_anchor)
            tc.setPosition(current.position(), QTextCursor.MoveMode.KeepAnchor)
            self._editor.setTextCursor(tc)
            return

    def _operate_visual(self, op):
        tc = self._editor.textCursor()
        if self._mode == VimMode.VISUAL_LINE:
            # Extend to full lines
            start = tc.selectionStart()
            end = tc.selectionEnd()
            tc.setPosition(start)
            tc.movePosition(QTextCursor.MoveOperation.StartOfBlock)
            start = tc.position()
            tc.setPosition(end)
            tc.movePosition(QTextCursor.MoveOperation.EndOfBlock)
            # Include the newline if not at document end
            if not tc.atEnd():
                tc.movePosition(QTextCursor.MoveOperation.Right)
            tc.setPosition(start, QTextCursor.MoveMode.KeepAnchor)
            selected = tc.selectedText()
            self._yank_buffer = selected
            self._yank_is_linewise = True
        else:
            selected = tc.selectedText()
            self._yank_buffer = selected
            self._yank_is_linewise = False

        if op == 'd':
            tc.removeSelectedText()
            self._editor.setTextCursor(tc)
            self._set_mode(VimMode.NORMAL)
        elif op == 'y':
            pos = tc.selectionStart()
            tc.clearSelection()
            tc.setPosition(pos)
            self._editor.setTextCursor(tc)
            self._set_mode(VimMode.NORMAL)
        elif op == 'c':
            tc.removeSelectedText()
            self._editor.setTextCursor(tc)
            self._set_mode(VimMode.INSERT)

    # ─── COMMAND mode ────────────────────────────────────────────────

    def _set_mode_raw(self, mode):
        """Set mode without clearing command buffer."""
        self._mode = mode
        self.mode_changed.emit(self._command_buffer)

    def _handle_command_key(self, event) -> bool:
        key = event.key()
        text = event.text()

        if key == Qt.Key.Key_Escape:
            self._command_buffer = ""
            self._set_mode(VimMode.NORMAL)
            return True

        if key == Qt.Key.Key_Return or key == Qt.Key.Key_Enter:
            self._execute_command()
            return True

        if key == Qt.Key.Key_Backspace:
            if len(self._command_buffer) > 1:
                self._command_buffer = self._command_buffer[:-1]
                self.mode_changed.emit(self._command_buffer)
            else:
                self._command_buffer = ""
                self._set_mode(VimMode.NORMAL)
            return True

        if text and text.isprintable():
            self._command_buffer += text
            self.mode_changed.emit(self._command_buffer)

        return True

    def _execute_command(self):
        buf = self._command_buffer
        self._command_buffer = ""

        if buf.startswith('/') or buf.startswith('?'):
            pattern = buf[1:]
            if pattern:
                self._search_pattern = pattern
                self._search_forward = buf[0] == '/'
                self._search_next(forward=self._search_forward)
            self._set_mode(VimMode.NORMAL)
            return

        if buf.startswith(':'):
            cmd = buf[1:].strip()
            if cmd == 'w':
                self.save_requested.emit()
            elif cmd == 'q':
                self.quit_requested.emit()
            elif cmd == 'wq' or cmd == 'x':
                self.save_requested.emit()
                self.quit_requested.emit()
            elif cmd.isdigit():
                self._goto_line(int(cmd))
            self._set_mode(VimMode.NORMAL)
            return

        self._set_mode(VimMode.NORMAL)

    # ─── Motion helpers ──────────────────────────────────────────────

    def _move_cursor(self, operation, count=1):
        tc = self._editor.textCursor()
        for _ in range(count):
            tc.movePosition(operation)
        self._editor.setTextCursor(tc)
        self._editor.ensureCursorVisible()
        self._clear_state()

    def _move_first_non_blank(self):
        tc = self._editor.textCursor()
        tc.movePosition(QTextCursor.MoveOperation.StartOfBlock)
        block_text = tc.block().text()
        indent = len(block_text) - len(block_text.lstrip())
        for _ in range(indent):
            tc.movePosition(QTextCursor.MoveOperation.Right)
        self._editor.setTextCursor(tc)
        self._editor.ensureCursorVisible()
        self._clear_state()

    def _goto_line(self, line_num):
        doc = self._editor.document()
        block_count = doc.blockCount()
        target = max(1, min(line_num, block_count))
        block = doc.findBlockByNumber(target - 1)
        tc = self._editor.textCursor()
        tc.setPosition(block.position())
        self._editor.setTextCursor(tc)
        self._editor.ensureCursorVisible()

    def _move_word_WORD(self, forward=True, count=1):
        """Move by WORD (whitespace-delimited)."""
        tc = self._editor.textCursor()
        text = self._editor.toPlainText()
        pos = tc.position()

        for _ in range(count):
            if forward:
                # Skip non-whitespace
                while pos < len(text) and not text[pos].isspace():
                    pos += 1
                # Skip whitespace
                while pos < len(text) and text[pos].isspace():
                    pos += 1
            else:
                if pos > 0:
                    pos -= 1
                # Skip whitespace
                while pos > 0 and text[pos].isspace():
                    pos -= 1
                # Skip non-whitespace
                while pos > 0 and not text[pos - 1].isspace():
                    pos -= 1

        tc.setPosition(pos)
        self._editor.setTextCursor(tc)
        self._editor.ensureCursorVisible()
        self._clear_state()

    def _move_end_of_word(self, count=1):
        tc = self._editor.textCursor()
        text = self._editor.toPlainText()
        pos = tc.position()

        for _ in range(count):
            if pos < len(text) - 1:
                pos += 1
            # Skip whitespace
            while pos < len(text) - 1 and text[pos].isspace():
                pos += 1
            # Skip word chars
            while pos < len(text) - 1 and text[pos + 1].isalnum() or (pos < len(text) - 1 and text[pos + 1] == '_'):
                pos += 1

        tc.setPosition(pos)
        self._editor.setTextCursor(tc)
        self._editor.ensureCursorVisible()
        self._clear_state()

    def _move_end_of_WORD(self, count=1):
        tc = self._editor.textCursor()
        text = self._editor.toPlainText()
        pos = tc.position()

        for _ in range(count):
            if pos < len(text) - 1:
                pos += 1
            while pos < len(text) - 1 and text[pos].isspace():
                pos += 1
            while pos < len(text) - 1 and not text[pos + 1].isspace():
                pos += 1

        tc.setPosition(pos)
        self._editor.setTextCursor(tc)
        self._editor.ensureCursorVisible()
        self._clear_state()

    def _move_paragraph(self, forward=True, count=1):
        tc = self._editor.textCursor()
        self._move_paragraph_cursor(tc, forward, count)
        self._editor.setTextCursor(tc)
        self._editor.ensureCursorVisible()
        self._clear_state()

    def _move_paragraph_cursor(self, tc, forward=True, count=1):
        doc = self._editor.document()
        block = tc.block()
        for _ in range(count):
            # Skip current paragraph (non-empty lines)
            while block.isValid() and block.text().strip():
                block = block.next() if forward else block.previous()
            # Skip empty lines
            while block.isValid() and not block.text().strip():
                block = block.next() if forward else block.previous()
        if block.isValid():
            tc.setPosition(block.position())
        elif forward:
            tc.movePosition(QTextCursor.MoveOperation.End)
        else:
            tc.movePosition(QTextCursor.MoveOperation.Start)

    # ─── Operation helpers ───────────────────────────────────────────

    def _delete_chars(self, count):
        tc = self._editor.textCursor()
        for _ in range(count):
            if not tc.atBlockEnd():
                tc.deleteChar()
        self._editor.setTextCursor(tc)

    def _delete_chars_before(self, count):
        tc = self._editor.textCursor()
        for _ in range(count):
            if tc.positionInBlock() > 0:
                tc.deletePreviousChar()
        self._editor.setTextCursor(tc)

    def _delete_lines(self, count):
        tc = self._editor.textCursor()
        tc.movePosition(QTextCursor.MoveOperation.StartOfBlock)
        start = tc.position()
        for _ in range(count):
            tc.movePosition(QTextCursor.MoveOperation.EndOfBlock)
            if not tc.atEnd():
                tc.movePosition(QTextCursor.MoveOperation.Right)  # include newline
        tc.setPosition(start, QTextCursor.MoveMode.KeepAnchor)
        self._yank_buffer = tc.selectedText()
        self._yank_is_linewise = True
        tc.removeSelectedText()
        self._editor.setTextCursor(tc)

    def _yank_lines(self, count):
        tc = self._editor.textCursor()
        pos = tc.position()
        tc.movePosition(QTextCursor.MoveOperation.StartOfBlock)
        start = tc.position()
        for _ in range(count):
            tc.movePosition(QTextCursor.MoveOperation.EndOfBlock)
            if not tc.atEnd():
                tc.movePosition(QTextCursor.MoveOperation.Right)
        tc.setPosition(start, QTextCursor.MoveMode.KeepAnchor)
        self._yank_buffer = tc.selectedText()
        self._yank_is_linewise = True
        tc.clearSelection()
        tc.setPosition(pos)
        self._editor.setTextCursor(tc)

    def _change_lines(self, count):
        tc = self._editor.textCursor()
        tc.movePosition(QTextCursor.MoveOperation.StartOfBlock)
        for _ in range(count - 1):
            tc.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.KeepAnchor)
        tc.movePosition(QTextCursor.MoveOperation.EndOfBlock, QTextCursor.MoveMode.KeepAnchor)
        self._yank_buffer = tc.selectedText()
        self._yank_is_linewise = True
        tc.removeSelectedText()
        self._editor.setTextCursor(tc)
        self._set_mode(VimMode.INSERT)

    def _paste(self, after=True):
        if not self._yank_buffer:
            return
        tc = self._editor.textCursor()
        # Convert paragraph separators back to newlines
        text = self._yank_buffer.replace('\u2029', '\n')
        if self._yank_is_linewise:
            if after:
                tc.movePosition(QTextCursor.MoveOperation.EndOfBlock)
                tc.insertText("\n" + text.rstrip('\n'))
            else:
                tc.movePosition(QTextCursor.MoveOperation.StartOfBlock)
                tc.insertText(text.rstrip('\n') + "\n")
                tc.movePosition(QTextCursor.MoveOperation.Up)
        else:
            if after and not tc.atBlockEnd():
                tc.movePosition(QTextCursor.MoveOperation.Right)
            tc.insertText(text)
        self._editor.setTextCursor(tc)

    def _join_lines(self, count):
        tc = self._editor.textCursor()
        for _ in range(count):
            tc.movePosition(QTextCursor.MoveOperation.EndOfBlock)
            if tc.atEnd():
                break
            tc.deleteChar()  # delete newline
            # Remove leading whitespace of next line and insert space
            block_text = tc.block().text()
            pos_in_block = tc.positionInBlock()
            remaining = block_text[pos_in_block:]
            stripped = remaining.lstrip()
            chars_to_remove = len(remaining) - len(stripped)
            for _ in range(chars_to_remove):
                tc.deleteChar()
            if pos_in_block > 0 and stripped:
                tc.insertText(" ")
        self._editor.setTextCursor(tc)

    def _toggle_case(self, count):
        tc = self._editor.textCursor()
        for _ in range(count):
            if tc.atBlockEnd():
                break
            tc.movePosition(QTextCursor.MoveOperation.Right, QTextCursor.MoveMode.KeepAnchor)
            ch = tc.selectedText()
            if ch.isupper():
                tc.insertText(ch.lower())
            else:
                tc.insertText(ch.upper())
        self._editor.setTextCursor(tc)

    # ─── Search ──────────────────────────────────────────────────────

    def _search_next(self, forward=True):
        if not self._search_pattern:
            return
        doc = self._editor.document()
        tc = self._editor.textCursor()

        if forward:
            found = doc.find(self._search_pattern, tc)
            if found.isNull():
                # Wrap around
                found = doc.find(self._search_pattern, 0)
        else:
            found = doc.find(self._search_pattern, tc,
                             QTextCursor.MoveOperation.Start if hasattr(QTextCursor.MoveOperation, 'Start') else 0)
            if found.isNull() or found.position() >= tc.position():
                # Search backward from current position
                search_tc = QTextCursor(tc)
                search_tc.movePosition(QTextCursor.MoveOperation.Start)
                # Manual backward search
                found = self._search_backward(self._search_pattern, tc.position())

        if found and not found.isNull():
            self._editor.setTextCursor(found)
            self._editor.ensureCursorVisible()

    def _search_backward(self, pattern, from_pos):
        """Search backward from position."""
        doc = self._editor.document()
        text = doc.toPlainText()
        # Search from end to beginning
        idx = text.rfind(pattern, 0, from_pos)
        if idx == -1:
            # Wrap around - search from end
            idx = text.rfind(pattern)
        if idx >= 0:
            tc = self._editor.textCursor()
            tc.setPosition(idx)
            tc.setPosition(idx + len(pattern), QTextCursor.MoveMode.KeepAnchor)
            return tc
        return None
