"""Incremental YARA syntax highlighting, independent of parser acceptance."""

from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont

from bisect import bisect_right
from yarax_editor import LanguageService, SourceMap
from yaraxgui.editor.backend import automatic_document_allowed


def _fmt(color: str, bold=False, italic=False) -> QTextCharFormat:
    f = QTextCharFormat()
    f.setForeground(QColor(color))
    if bold:
        f.setFontWeight(QFont.Weight.Bold)
    if italic:
        f.setFontItalic(True)
    return f

class YaraHighlighter(QSyntaxHighlighter):
    """Highlight lexical spans without confusing comments, strings or patterns."""

    def __init__(self, document, theme=None):
        super().__init__(None)
        self.setParent(document)
        self.current_theme = theme
        self._service = LanguageService()
        self._cached_revision = None
        self._source_document = None
        self._spans = []
        self._ends = []
        self.init_theme_colors()
        self.setDocument(document)

    def setDocument(self, document):
        if self._source_document is not None:
            self._source_document.contentsChange.disconnect(self._sync_size)
        self._source_document = document
        if document is not None:
            # Register before Qt's highlighter callback: a large paste/load must
            # detach coloring before Qt dispatches highlightBlock for every line.
            document.contentsChange.connect(self._sync_size)
        self._sync_size()

    def _sync_size(self, *_args):
        self._cached_revision = None
        source = self._source_document
        target = source if source is not None and automatic_document_allowed(source) else None
        if self.document() is not target:
            super().setDocument(target)
        if target is None:
            self._spans = []
            self._ends = []

    def init_theme_colors(self):
        """Initialize syntax highlighting colors based on current theme"""
        if self.current_theme and hasattr(self.current_theme, 'colors'):
            # Use theme-specific syntax colors
            colors = self.current_theme.colors
            
            # Use the new syntax-specific colors if available
            if hasattr(colors, 'syntax_keyword'):
                self.fmt_decl      = _fmt(colors.syntax_keyword, bold=True)     # rule, import, private, global
                self.fmt_logic     = _fmt(colors.syntax_logic)                  # and, or, not, any, all, of, them
                self.fmt_builtin   = _fmt(colors.syntax_builtin)               # filesize, entrypoint, uint8, etc.
                self.fmt_modifiers = _fmt(colors.syntax_modifier)              # ascii, wide, nocase, fullword
                self.fmt_module    = _fmt(colors.syntax_module, bold=True)     # pe, elf, math, hash
                self.fmt_symref    = _fmt(colors.syntax_symbol)                # $a, #a, @a[0]
                self.fmt_number    = _fmt(colors.syntax_number)                # 42, 0x1A, etc.
                self.fmt_string    = _fmt(colors.syntax_string)                # "text", 'text'
                self.fmt_regex     = _fmt(colors.syntax_regex)                 # /pattern/flags
                self.fmt_hexstr    = _fmt(colors.syntax_hex)                   # { 41 42 43 }
                self.fmt_comment   = _fmt(colors.syntax_comment, italic=True)  # // and /* */
                
                # Additional syntax formats
                self.fmt_identifier = _fmt(getattr(colors, 'syntax_identifier', colors.syntax_symbol))  # Rule names, identifiers
                self.fmt_meta_key   = _fmt(getattr(colors, 'syntax_meta_key', colors.syntax_builtin))  # Meta keys
                self.fmt_tag        = _fmt(getattr(colors, 'syntax_tag', colors.syntax_modifier))      # Rule tags
                self.fmt_condition  = _fmt(getattr(colors, 'syntax_condition', colors.syntax_logic))   # Condition keywords
                self.fmt_operator   = _fmt(getattr(colors, 'syntax_operator', colors.syntax_logic))    # Operators +, -, *, etc.
                self.fmt_literal    = _fmt(getattr(colors, 'syntax_literal', colors.syntax_string))    # String/hex literals
                self.fmt_function   = _fmt(getattr(colors, 'syntax_function', colors.syntax_module))   # Function calls
                self.fmt_section    = _fmt(getattr(colors, 'syntax_section', colors.syntax_keyword))   # meta:, strings:, condition:
            else:
                # Fallback to old system for compatibility
                if self.current_theme.name == "Dark":
                    # Dark theme colors (VS Code style)
                    self.fmt_decl      = _fmt("#569cd6", bold=True)
                    self.fmt_logic     = _fmt("#c586c0")
                    self.fmt_builtin   = _fmt("#4ec9b0")
                    self.fmt_modifiers = _fmt("#dcdcaa")
                    self.fmt_module    = _fmt("#4fc1ff", bold=True)
                    self.fmt_symref    = _fmt("#9cdcfe")
                    self.fmt_number    = _fmt("#b5cea8")
                    self.fmt_string    = _fmt("#ce9178")
                    self.fmt_regex     = _fmt("#d19a66")
                    self.fmt_hexstr    = _fmt("#d7ba7d")
                    self.fmt_comment   = _fmt("#6a9955", italic=True)
                    # Additional syntax formats
                    self.fmt_identifier = _fmt("#FFA366")  # Light orange for identifiers
                    self.fmt_meta_key   = _fmt("#4ec9b0")
                    self.fmt_tag        = _fmt("#dcdcaa")
                    self.fmt_condition  = _fmt("#c586c0")
                    self.fmt_operator   = _fmt("#d4d4d4")
                    self.fmt_literal    = _fmt("#ce9178")
                    self.fmt_function   = _fmt("#4fc1ff", bold=True)
                    self.fmt_section    = _fmt("#569cd6", bold=True)
                else:
                    # Light theme colors (VS Code light style)
                    self.fmt_decl      = _fmt("#0000ff", bold=True)
                    self.fmt_logic     = _fmt("#af00db")
                    self.fmt_builtin   = _fmt("#267f99")
                    self.fmt_modifiers = _fmt("#795e26")
                    self.fmt_module    = _fmt("#001080", bold=True)
                    self.fmt_symref    = _fmt("#001080")
                    self.fmt_number    = _fmt("#098658")
                    self.fmt_string    = _fmt("#a31515")
                    self.fmt_regex     = _fmt("#811f3f")
                    self.fmt_hexstr    = _fmt("#795e26")
                    self.fmt_comment   = _fmt("#008000", italic=True)
                    # Additional syntax formats
                    self.fmt_identifier = _fmt("#D2691E")  # Darker orange for light theme
                    self.fmt_meta_key   = _fmt("#267f99")
                    self.fmt_tag        = _fmt("#795e26")
                    self.fmt_condition  = _fmt("#af00db")
                    self.fmt_operator   = _fmt("#af00db")
                    self.fmt_literal    = _fmt("#a31515")
                    self.fmt_function   = _fmt("#001080", bold=True)
                    self.fmt_section    = _fmt("#0000ff", bold=True)
        else:
            # Default colors (dark theme fallback)
            self.fmt_decl      = _fmt("#5EA1FF", bold=True)
            self.fmt_logic     = _fmt("#FF8AE2")
            self.fmt_builtin   = _fmt("#33C2C2")
            self.fmt_modifiers = _fmt("#E2B714")
            self.fmt_module    = _fmt("#8CE99A", bold=True)
            self.fmt_symref    = _fmt("#7CD5FF")
            self.fmt_number    = _fmt("#9CDCFE")
            self.fmt_string    = _fmt("#CE9178")
            self.fmt_regex     = _fmt("#D19A66")
            self.fmt_hexstr    = _fmt("#E5C07B")
            self.fmt_comment   = _fmt("#6A9955", italic=True)
            # Additional syntax formats
            self.fmt_identifier = _fmt("#FFA366")  # Light orange for identifiers
            self.fmt_meta_key   = _fmt("#33C2C2")
            self.fmt_tag        = _fmt("#E2B714")
            self.fmt_condition  = _fmt("#FF8AE2")
            self.fmt_operator   = _fmt("#FF8AE2")
            self.fmt_literal    = _fmt("#CE9178")
            self.fmt_function   = _fmt("#8CE99A", bold=True)
            self.fmt_section    = _fmt("#5EA1FF", bold=True)

    def update_theme(self, theme):
        self.current_theme = theme
        self.init_theme_colors()
        self.rehighlight()

    def highlightBlock(self, text):
        document = self.document()
        if document is None:
            return
        revision = document.revision()
        if revision != self._cached_revision:
            self._cached_revision = revision
            source = document.toPlainText()
            mapping = SourceMap(source)
            self._spans = [(mapping.utf16[span.start], mapping.utf16[span.end], kind,
                            source[span.start:span.end])
                           for span, kind in self._service.highlights(source)]
            self._ends = [end for _, end, _, _ in self._spans]
        # Changing state propagates lexical context edits to subsequent blocks.
        self.setCurrentBlockState(revision % 2147483647)
        start = self.currentBlock().position()
        end = start + len(text.encode("utf-16-le")) // 2
        formats = {"comment": self.fmt_comment, "string": self.fmt_string,
                   "multiline_string": self.fmt_string, "regex": self.fmt_regex,
                   "hex": self.fmt_hexstr, "reference": self.fmt_symref,
                   "number": self.fmt_number, "operator": self.fmt_operator,
                   "keyword": self.fmt_logic, "identifier": self.fmt_identifier}
        index = bisect_right(self._ends, start)
        for span_index in range(index, len(self._spans)):
            left, right, kind, word = self._spans[span_index]
            if left >= end:
                break
            fmt = formats.get(kind)
            if kind in ("identifier", "keyword"):
                if word in {"rule", "import", "include", "private", "global"}:
                    fmt = self.fmt_decl
                elif word in {"meta", "strings", "condition"}:
                    fmt = self.fmt_section
                elif word in self._service.catalog.builtins or word in {"filesize", "entrypoint"}:
                    fmt = self.fmt_builtin
            if fmt is not None:
                left, right = max(start, left), min(end, right)
                self.setFormat(left - start, right - left, fmt)
