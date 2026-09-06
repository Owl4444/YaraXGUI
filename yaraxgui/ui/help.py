"""Searchable offline documentation browser backed by bundled Markdown files."""
from importlib import resources
from pathlib import Path
from yaraxgui.paths import resource_root
import re

from PySide6.QtCore import Qt, QTimer, QUrl, QEvent
from PySide6.QtGui import (QDesktopServices, QShortcut, QKeySequence, QTextCursor,
    QTextDocument, QTextBlockFormat, QTextCharFormat, QTextFormat, QTextFrameFormat,
    QTextLength, QFontDatabase, QPalette)
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QLineEdit, QSplitter,
    QListWidget, QTextBrowser, QLabel, QWidget, QHBoxLayout, QToolButton)
from yaraxgui.recovery.store import IO_POOL


def _offline_markdown(body, path, reference):
    """Adapt upstream Hugo links and callouts without changing bundled sources."""
    def reference_link(match):
        target = match.group(1)
        candidates = [path.parent / target, reference / target]
        candidates += [p for p in reference.rglob(Path(target).name)
                       if 'generated_modules' not in p.parts]
        candidate = next((p for p in candidates if p.is_file()), None)
        return candidate.resolve().as_uri() if candidate else 'https://virustotal.github.io/yara-x/docs/' + target

    body = re.sub(r'\{\{<\s*ref\s+["\']([^"\']+)["\']\s*>\}\}', reference_link, body)
    def callout(match):
        title = re.search(r'title=["\']([^"\']+)["\']', match.group(1))
        return '\n**' + (title.group(1) if title else 'Note') + '**\n'
    body = re.sub(r'\{\{<\s*callout\b(.*?)>\}\}', callout, body, flags=re.DOTALL)
    body = re.sub(r'\{\{<\s*/callout\s*>\}\}', '', body)
    def docs_link(match):
        target = reference / match.group(1).rstrip('/')
        candidates = [target.with_suffix('.md'), target / '_index.md']
        candidate = next((p for p in candidates if p.is_file()), None)
        return '](' + (candidate.resolve().as_uri() if candidate else
                        'https://virustotal.github.io/yara-x/docs/' + match.group(1))
    return re.sub(r'\]\(/docs/([^\s)#]+)', docs_link, body)


def documentation_pages():
    root = resource_root()
    pages = []
    for name, filename in (('User Guide', 'USER_GUIDE.md'),
                           ('Keyboard Shortcuts', 'KEYBOARD_SHORTCUTS.md'),
                           ('XPRESS Huffman Recipe', 'XPRESS_HUFFMAN.md'),
                           ('Recovery & Troubleshooting', 'RECOVERY_AND_TROUBLESHOOTING.md')):
        path = root / 'docs' / filename
        pages.append((name, path, path.read_text(encoding='utf-8')))
    reference = Path(str(resources.files('yarax_editor').joinpath('data/reference')))
    categories = {'writing_rules': 'Language', 'generated_modules': 'Modules',
                  'modules': 'Module Guides', 'intro': 'Getting Started',
                  'api': 'API', 'cli': 'Command Line'}
    for path in sorted(Path(str(reference)).rglob('*.md')):
        relative = path.relative_to(str(reference))
        body = path.read_text(encoding='utf-8')
        name = path.stem.replace('_', ' ').title() if path.stem != '_index' else 'Overview'
        if relative.parts[0] == 'generated_modules':
            name = path.stem
        if body.startswith('---\n') and '\n---' in body[4:]:
            front, body = body[4:].split('\n---', 1)
            match = re.search(r'^title:\s*["\']?(.*?)["\']?\s*$', front, re.MULTILINE)
            if match:
                name = match.group(1)
            body = '# ' + name + '\n' + body.lstrip()
        category = categories.get(relative.parts[0], 'Overview')
        title = f'YARA-X Reference / {category} / {name}'
        pages.append((title, path, _offline_markdown(body, path, reference)))
    # The toolkit's compatibility contract is shipped as an app help page.
    path = root / 'docs' / 'EDITOR_COMPATIBILITY.md'
    if path.exists():
        pages.append(('YARA-X Reference / Compatibility', path, path.read_text(encoding='utf-8')))
    order = ['User Guide', 'Keyboard Shortcuts', 'Recovery & Troubleshooting',
             'YARA-X Reference / Compatibility', 'YARA-X Reference / Getting Started',
             'YARA-X Reference / Language', 'YARA-X Reference / Modules',
             'YARA-X Reference / Module Guides', 'YARA-X Reference / API',
             'YARA-X Reference / Command Line', 'YARA-X Reference / Overview']
    return sorted(pages, key=lambda page: (
        next((i for i, prefix in enumerate(order) if page[0].startswith(prefix)), len(order)), page[0]))


class HelpViewer(QDialog):
    def __init__(self, topic='User Guide', parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle('YaraXGUI Help — Offline Documentation')
        self.resize(1050, 720)
        self._topic = topic
        self._pages = []
        self._visible = []
        layout = QVBoxLayout(self)
        self._search = QLineEdit()
        self._search.setPlaceholderText('Search offline documentation titles and contents…')
        layout.addWidget(self._search)
        splitter = QSplitter()
        self._list = QListWidget()
        self._browser = QTextBrowser()
        self._browser.setObjectName('offlineHelpDocument')
        self._browser.setOpenLinks(False)
        self._browser.anchorClicked.connect(self._link)
        splitter.addWidget(self._list)
        splitter.addWidget(self._browser)
        splitter.setSizes([300, 750])
        layout.addWidget(splitter, 1)
        self._find_bar = QWidget()
        find_layout = QHBoxLayout(self._find_bar)
        find_layout.setContentsMargins(0, 0, 0, 0)
        self._find_text = QLineEdit()
        self._find_text.setPlaceholderText('Find in this page…')
        self._find_text.setClearButtonEnabled(True)
        self._find_text.installEventFilter(self)
        find_layout.addWidget(self._find_text, 1)
        self._find_status = QLabel()
        find_layout.addWidget(self._find_status)
        for label, callback in [('Previous', lambda: self._find(backwards=True)),
                                ('Next', self._find), ('Close', self._close_find)]:
            button = QToolButton()
            button.setText(label)
            button.clicked.connect(callback)
            find_layout.addWidget(button)
        layout.addWidget(self._find_bar)
        self._find_bar.hide()
        self._find_text.textChanged.connect(self._restart_find)
        self._find_text.returnPressed.connect(self._find)
        for sequence, callback in [('Ctrl+F', self._open_find), ('F3', self._find),
                                   ('Shift+F3', lambda: self._find(backwards=True)),
                                   ('Ctrl+G', self._find),
                                   ('Ctrl+Shift+G', lambda: self._find(backwards=True))]:
            shortcut = QShortcut(QKeySequence(sequence), self)
            shortcut.activated.connect(callback)
        self._status = QLabel('Loading bundled documentation…')
        layout.addWidget(self._status)
        self._list.currentRowChanged.connect(self._show_page)
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(200)
        self._debounce.timeout.connect(self._filter)
        self._search.textChanged.connect(lambda: self._debounce.start())
        self._future = IO_POOL.submit(documentation_pages)
        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._loaded)
        self._timer.start()
        self._browser.installEventFilter(self)

    def _open_find(self):
        self._find_bar.show()
        selected = self._browser.textCursor().selectedText()
        if selected and '\u2029' not in selected:
            self._find_text.setText(selected)
        self._find_text.setFocus()
        self._find_text.selectAll()

    def _close_find(self):
        self._find_bar.hide()
        self._browser.setFocus()

    def eventFilter(self, watched, event):
        if watched is self._browser and self._pages and event.type() in (
                QEvent.Type.PaletteChange, QEvent.Type.FontChange):
            self._style_document()
        if watched is self._find_text and event.type() == QEvent.Type.KeyPress:
            if event.key() == Qt.Key.Key_Escape:
                self._close_find()
                return True
            if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                self._find(backwards=True)
                return True
        return super().eventFilter(watched, event)

    def _restart_find(self):
        cursor = self._browser.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self._browser.setTextCursor(cursor)
        self._find()

    def _find(self, backwards=False):
        query = self._find_text.text()
        if not query:
            self._find_status.clear()
            return
        flags = QTextDocument.FindFlag.FindBackward if backwards else QTextDocument.FindFlag(0)
        cursor = self._browser.textCursor()
        found = self._browser.document().find(query, cursor, flags)
        wrapped = False
        if found.isNull():
            wrapped = True
            cursor.movePosition(QTextCursor.MoveOperation.End if backwards else QTextCursor.MoveOperation.Start)
            found = self._browser.document().find(query, cursor, flags)
        if found.isNull():
            self._find_status.setText('No matches')
        else:
            self._browser.setTextCursor(found)
            self._browser.ensureCursorVisible()
            self._find_status.setText('Wrapped to end' if wrapped and backwards else
                                      'Wrapped to start' if wrapped else 'Match found')

    def _style_document(self):
        """Keep Qt's Markdown structure, then give prose, code and tables room."""
        document = self._browser.document()
        font = self.font()
        # Reading text needs more room than compact application controls.
        font.setPointSizeF(max(11, font.pointSizeF()))
        document.setDefaultFont(font)
        document.setDocumentMargin(24)
        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        base = self._browser.palette().color(QPalette.ColorRole.Base)
        background = base.lighter(130) if base.lightness() < 128 else base.darker(104)
        block = document.begin()
        while block.isValid():
            cursor = QTextCursor(block)
            fmt = block.blockFormat()
            heading = fmt.headingLevel()
            code = fmt.hasProperty(QTextFormat.Property.BlockCodeFence) or fmt.nonBreakableLines()
            fmt.setLineHeight(135 if not code else 100, QTextBlockFormat.LineHeightTypes.ProportionalHeight.value)
            fmt.setTopMargin(24 if heading else 0 if code else 5)
            fmt.setBottomMargin(12 if heading else 0 if code else 10)
            if code:
                fmt.setBackground(background)
                fmt.setLeftMargin(12)
                fmt.setRightMargin(12)
            if cursor.currentTable() is not None:
                fmt.setTopMargin(0)
                fmt.setBottomMargin(0)
            cursor.setBlockFormat(fmt)
            cursor.select(QTextCursor.SelectionType.BlockUnderCursor)
            char = QTextCharFormat()
            if heading:
                char.setFontPointSize(font.pointSizeF() * {1: 1.8, 2: 1.4, 3: 1.18}.get(heading, 1.05))
            elif code:
                char.setFontFamilies([mono.family()])
                char.setFontPointSize(font.pointSizeF())
            if heading or code:
                cursor.mergeCharFormat(char)
            block = block.next()
        def style_tables(frame):
            from PySide6.QtGui import QTextTable
            for child in frame.childFrames():
                if isinstance(child, QTextTable):
                    fmt = child.format()
                    fmt.setCellPadding(8)
                    fmt.setCellSpacing(0)
                    fmt.setBorder(1)
                    fmt.setBorderStyle(QTextFrameFormat.BorderStyle.BorderStyle_Solid)
                    fmt.setBorderCollapse(True)
                    fmt.setWidth(QTextLength(QTextLength.Type.PercentageLength, 100))
                    fmt.setBorderBrush(self._browser.palette().color(QPalette.ColorRole.Mid))
                    child.setFormat(fmt)
                    for column in range(child.columns()):
                        cell = child.cellAt(0, column)
                        cell_format = cell.format()
                        cell_format.setBackground(background)
                        cell.setFormat(cell_format)
                style_tables(child)
        style_tables(document.rootFrame())

    def _loaded(self):
        if not self._future.done():
            return
        self._timer.stop()
        try:
            self._pages = self._future.result()
        except Exception as exc:
            self._status.setText(f'Could not load offline documentation: {exc}')
            return
        self._searchable = [(title + '\n' + body).lower() for title, _, body in self._pages]
        self._filter()
        for row, index in enumerate(self._visible):
            if self._pages[index][0].startswith(self._topic):
                self._list.setCurrentRow(row)
                break

    def _filter(self):
        query = self._search.text().strip().lower()
        self._visible = [i for i in range(len(self._pages)) if not query or query in self._searchable[i]]
        self._list.clear()
        self._list.addItems([self._pages[i][0].removeprefix('YARA-X Reference / ')
                             for i in self._visible])
        self._status.setText(f'{len(self._visible)} offline documents')
        if self._visible:
            self._list.setCurrentRow(0)
        else:
            self._browser.clear()
            self._find_status.clear()

    def _show_page(self, row):
        if row < 0 or row >= len(self._visible):
            return
        title, path, body = self._pages[self._visible[row]]
        self._current_path = path
        self._browser.document().setBaseUrl(QUrl.fromLocalFile(str(path.parent) + '/'))
        self._browser.setMarkdown(body)
        self._style_document()
        if self._find_bar.isVisible():
            self._restart_find()

    def _link(self, url):
        if url.scheme() in ('https', 'http'):
            QDesktopServices.openUrl(url)
            return
        if not url.path():
            self._browser.scrollToAnchor(url.fragment())
            return
        path = Path(url.toLocalFile()) if url.isLocalFile() else self._current_path.parent / url.path()
        for index, (_, candidate, _) in enumerate(self._pages):
            if path.resolve() == candidate.resolve():
                self._search.clear()
                self._debounce.stop()
                self._filter()
                self._list.setCurrentRow(self._visible.index(index))
                if url.fragment():
                    self._browser.scrollToAnchor(url.fragment())
                return
        self._status.setText('This link is not included in the offline reference.')
