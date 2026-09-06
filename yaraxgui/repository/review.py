"""Read-only review of the exact repository changes about to be submitted."""

from difflib import SequenceMatcher

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFontDatabase, QSyntaxHighlighter, QTextCharFormat, QTextOption
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QHBoxLayout, QLabel, QPlainTextEdit,
    QPushButton, QVBoxLayout,
)


def rule_diff(before: str, after: str) -> tuple[str, bool]:
    """Return a complete unified diff, bounding matching work on large inputs.

    Large changes use common prefix/suffix matching in linear time. That can
    show more replaced lines, but never omits changes or blocks on quadratic
    matching of repetitive rules. Rendering is paged separately.
    """
    if before == after:
        return 'No changes.\n', False
    old, new = before.splitlines(keepends=True), after.splitlines(keepends=True)
    coarse = len(before) + len(after) > 256 * 1024 or len(old) + len(new) > 4000
    if coarse:
        prefix = 0
        while prefix < min(len(old), len(new)) and old[prefix] == new[prefix]:
            prefix += 1
        tail = 0
        while (tail < min(len(old), len(new)) - prefix
               and old[len(old) - tail - 1] == new[len(new) - tail - 1]):
            tail += 1
        old_end, new_end = len(old) - tail, len(new) - tail
        tag = 'insert' if prefix == old_end else 'delete' if prefix == new_end else 'replace'
        groups = [[('equal', max(0, prefix - 3), prefix, max(0, prefix - 3), prefix),
                   (tag, prefix, old_end, prefix, new_end),
                   ('equal', old_end, min(len(old), old_end + 3),
                    new_end, min(len(new), new_end + 3))]]
    else:
        groups = SequenceMatcher(None, old, new).get_grouped_opcodes(3)

    output = ['--- Saved version\n', '+++ Proposed version\n']

    def append(prefix, lines):
        for line in lines:
            # Make CRLF differences visible; preserve missing final newlines.
            output.append(prefix + line.replace('\r', '[CR]'))
            if not line.endswith('\n'):
                output.append('\n\\ No newline at end of file\n')

    for group in groups:
        first, last = group[0], group[-1]
        old_count, new_count = last[2] - first[1], last[4] - first[3]
        output.append(f'@@ -{first[1] + bool(old_count)},{old_count} '
                      f'+{first[3] + bool(new_count)},{new_count} @@\n')
        for tag, i, j, k, l in group:
            if tag == 'equal':
                append(' ', old[i:j])
            if tag in ('delete', 'replace'):
                append('-', old[i:j])
            if tag in ('insert', 'replace'):
                append('+', new[k:l])
    return ''.join(output), coarse


class _DiffHighlighter(QSyntaxHighlighter):
    continuation = False

    def highlightBlock(self, text):
        if self.continuation and self.currentBlock().blockNumber() == 0:
            return
        if text.startswith('+'):
            background, foreground = '#d9f5df', '#145c2c'
        elif text.startswith('-'):
            background, foreground = '#ffe1e1', '#862424'
        elif text.startswith('@@'):
            background, foreground = '#deedff', '#204a80'
        else:
            return
        fmt = QTextCharFormat()
        fmt.setBackground(QColor(background))
        fmt.setForeground(QColor(foreground))
        self.setFormat(0, len(text), fmt)


class RuleUpdateReviewDialog(QDialog):
    PAGE_CHARS = 64000

    def __init__(self, name: str, location: str, before: str, after: str,
                 parent=None, *, kind='rule text'):
        super().__init__(parent)
        self.setWindowTitle('Review Repository Update')
        self.setMinimumSize(640, 420)
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        available = self.screen().availableGeometry()
        self.resize(min(1100, int(available.width() * .92)), min(760, int(available.height() * .9)))
        layout = QVBoxLayout(self)
        target = QLabel(f'Update {kind}: {name}\nRepository: {location}')
        target.setTextFormat(Qt.TextFormat.PlainText)
        target.setWordWrap(True)
        layout.addWidget(target)
        diff, coarse = rule_diff(before, after)
        self._versions = [diff, before, after]
        legend = QLabel('− Red: removed     + Green: added     [CR]: carriage return\n'
                        'Review the changes, then choose Confirm Update to save.')
        legend.setWordWrap(True)
        layout.addWidget(legend)
        if coarse:
            note = QLabel('Large update: the changed region is shown as a complete replacement '
                          'to keep comparison responsive. No changes are omitted.')
            note.setWordWrap(True)
            layout.addWidget(note)
        controls = QHBoxLayout()
        self._mode = QComboBox()
        self._mode.addItems(['Changes', 'Saved version', 'Proposed version'])
        self._mode.currentIndexChanged.connect(self._select_version)
        controls.addWidget(self._mode)
        whitespace = QCheckBox('Show whitespace')
        whitespace.toggled.connect(self._show_whitespace)
        controls.addWidget(whitespace)
        controls.addStretch()
        layout.addLayout(controls)
        self._view = QPlainTextEdit()
        self._view.setReadOnly(True)
        self._view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        font.setPointSize(max(11, self.font().pointSize()))
        self._view.setFont(font)
        self._highlighter = _DiffHighlighter(self._view.document())
        layout.addWidget(self._view, 1)
        paging = QHBoxLayout()
        self._previous = QPushButton('Previous Page')
        self._previous.clicked.connect(lambda: self._show_page(self._page - 1))
        self._next = QPushButton('Next Page')
        self._next.clicked.connect(lambda: self._show_page(self._page + 1))
        self._page_label = QLabel()
        paging.addWidget(self._previous)
        paging.addWidget(self._page_label, 1)
        paging.addWidget(self._next)
        layout.addLayout(paging)
        buttons = QHBoxLayout()
        buttons.addStretch()
        self._cancel = QPushButton('Cancel')
        self._cancel.clicked.connect(self.reject)
        self._confirm = QPushButton('Confirm Update')
        self._confirm.clicked.connect(self.accept)
        self._confirm.setAutoDefault(False)
        self._confirm.setDefault(False)
        self._confirm.setEnabled(before != after)
        self._cancel.setDefault(True)
        buttons.addWidget(self._cancel)
        buttons.addWidget(self._confirm)
        layout.addLayout(buttons)
        # Navigation buttons must never become the Enter/default action either.
        self._previous.setAutoDefault(False)
        self._next.setAutoDefault(False)
        self._select_version(0)
        self._cancel.setFocus()

    def _select_version(self, index):
        self._highlighter.setDocument(self._view.document() if index == 0 else None)
        self._text = self._versions[index]
        self._pages = [0]
        while self._pages[-1] < len(self._text):
            start = self._pages[-1]
            end = min(len(self._text), start + self.PAGE_CHARS)
            if end < len(self._text):
                newline = self._text.rfind('\n', start, end)
                if newline >= start:
                    end = newline + 1
            self._pages.append(end)
        if len(self._pages) == 1:
            self._pages.append(0)
        self._show_page(0)

    def _show_page(self, page):
        self._page = max(0, min(page, len(self._pages) - 2))
        start, end = self._pages[self._page:self._page + 2]
        continuation = start > 0 and self._text[start - 1] != '\n'
        self._highlighter.continuation = continuation
        self._view.setPlainText(self._text[start:end])
        self._previous.setEnabled(self._page > 0)
        self._next.setEnabled(self._page < len(self._pages) - 2)
        self._page_label.setText(f'Page {self._page + 1} of {len(self._pages) - 1}'
                                + (' · continuing the previous line' if continuation else ''))
        for widget in (self._previous, self._next, self._page_label):
            widget.setVisible(len(self._pages) > 2)

    def _show_whitespace(self, enabled):
        option = self._view.document().defaultTextOption()
        option.setFlags(QTextOption.Flag.ShowTabsAndSpaces if enabled else QTextOption.Flag(0))
        self._view.document().setDefaultTextOption(option)
