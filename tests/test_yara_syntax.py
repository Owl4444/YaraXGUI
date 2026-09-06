"""Compile, format, match and render tricky source through the actual app paths."""

import pytest
import yara_x
from PySide6.QtGui import QTextCharFormat, QTextCursor, QTextDocument

from yarax_editor import LanguageService
from yarax_editor.lexer import noncode_at
from yaraxgui.scanning.scanner import YaraScanner, compute_size_bounds, _compute_bounds_via_regex, _strip_comments
from yaraxgui.editor.highlighter import YaraHighlighter
from yaraxgui.editor.services import mask_source


WITH_CONDITIONS = [
    "with size = filesize : (size == 2)",
    "with first = uint8(0), second = uint8(1) : (first == 65 and second == 66)",
    "with outer = filesize : (with inner = outer + 1 : (inner == 3))",
    "for all offset in (0..1) : (with value = uint8(offset) : (value >= 65))",
    'with marker = "// /* literal */" : (marker == "// /* literal */" and filesize == 2)',
    """with /* a binding */
        size /* not a syntax separator */ = filesize // after value
        : /* before expression */ (
            size == 2 /* with fake = 0 : (false) */
        )""",
]


@pytest.mark.parametrize("condition", WITH_CONDITIONS)
def test_with_expressions_validate_format_and_match(condition):
    source = f"rule with_case {{ condition: {condition} }}"
    scanner = YaraScanner()
    validation = scanner.validate_syntax(source)
    assert validation["valid"], validation
    assert validation["rules_count"] == 1
    assert "with_case" in scanner.get_rule_info(source)
    assert scanner.compile_rules(source).scan(b"AB").matching_rules
    formatted = scanner.format_rules(source)
    assert scanner.compile_rules(formatted).scan(b"AB").matching_rules
    assert not scanner.compile_rules(formatted).scan(b"").matching_rules


COMMENT_RULE = r'''
/* A multiline comment with "quotes", // slashes, and rule fake { condition: false }
   with broken : ( ignored syntax
*/
rule comments_and_literals : test {
    meta:
        url = "https://example.test/path/*literal*/"
        description = """
            A \"quoted\" URL: https://example.test/path
            // This is metadata, not a line comment.
            /* This is metadata too. */
        """
    strings:
        $url = "https://example.test/path"
        $quote = "say \"//\" and /* literal */"
        $regex = /https?:\/\/example[.]test\/path/
        $hex = {
            41 /* hex comment */
            42 // another comment
        }
    condition:
        with size = filesize : (
            size > 0 and any of them
        ) // real trailing comment
}
'''


def test_comment_and_literal_corpus_roundtrips_without_changing_metadata():
    scanner = YaraScanner()
    assert scanner.validate_syntax(COMMENT_RULE)["valid"]
    rules = scanner.compile_rules(COMMENT_RULE)
    formatted = scanner.format_rules(COMMENT_RULE)
    formatted_rules = scanner.compile_rules(formatted)
    assert list(next(iter(rules)).metadata) == list(next(iter(formatted_rules)).metadata)
    assert "hex comment" in formatted and "real trailing comment" in formatted
    for data in (b"AB", b"https://example.test/path", b'say "//" and /* literal */'):
        assert rules.scan(data).matching_rules
        assert formatted_rules.scan(data).matching_rules
    assert not rules.scan(b"unrelated").matching_rules


@pytest.mark.parametrize("source", [
    "rule invalid { condition: with value = 1 (value == 1) }",
    "rule invalid { condition: with value = 1 : (value == 1 }",
    "rule invalid { condition: (with value = 1 : (value == 1)) and value == 1 }",
    "rule invalid { condition: with value = unknown : (value == 1) }",
    'rule invalid { meta: value = "unterminated\n condition: true }',
    "rule invalid { /* unterminated comment\n condition: true }",
    "rule invalid { condition: with value = 1 : (value == ) }",
    "rule invalid { condition: with small = filesize < 2 : (true) }",
    "rule invalid { condition: (filesize < 2) == false }",
])
def test_invalid_source_produces_real_compiler_diagnostics(source):
    result = YaraScanner().validate_syntax(source)
    assert result["valid"] is False
    assert result["errors"]
    assert result["errors"][0]["line"] >= 1
    with pytest.raises(yara_x.CompileError):
        YaraScanner().compile_rules(source)


def formatted_at(document, python_position):
    text = document.toPlainText()
    qt_position = len(text[:python_position].encode("utf-16-le")) // 2
    block = document.findBlock(qt_position)
    for span in block.layout().formats():
        if span.start <= qt_position - block.position() < span.start + span.length:
            return QTextCharFormat(span.format)
    raise AssertionError(f"No highlight at {python_position}: {text[python_position:python_position + 20]!r}")


@pytest.fixture
def highlighted(app):
    documents = []

    def create(text):
        document = QTextDocument(text)
        document.documentLayout()
        highlighter = YaraHighlighter(document)
        highlighter.rehighlight()
        documents.append((document, highlighter))
        return document, highlighter

    yield create
    for document, highlighter in documents:
        highlighter.setDocument(None)
        document.deleteLater()


def test_comment_markers_in_strings_and_multiline_metadata_remain_strings(highlighted):
    document, highlighter = highlighted(COMMENT_RULE)
    for marker in ("//example.test/path/*literal*/", "/*literal*/", "// This is metadata",
                   "/* This is metadata", "say ", r'A \"quoted\"'):
        offset = COMMENT_RULE.index(marker)
        assert formatted_at(document, offset).foreground() == highlighter.fmt_string.foreground()
    for marker in ("A multiline comment", "with broken", "hex comment", "another comment", "real trailing comment"):
        assert formatted_at(document, COMMENT_RULE.index(marker)).foreground() == highlighter.fmt_comment.foreground()
    assert formatted_at(document, COMMENT_RULE.index("with size")).foreground() == highlighter.fmt_logic.foreground()
    assert formatted_at(document, COMMENT_RULE.index("https?:")).foreground() == highlighter.fmt_regex.foreground()


@pytest.mark.parametrize("literal", [
    r'"http://host/*marker*/"',
    r'"escaped \"// not a comment\""',
    r'"backslashes \\"',
    r'/[\/][\/]/',
])
def test_trailing_comment_starts_after_literal_closes(literal, highlighted):
    source = f"{literal} // actual comment"
    document, highlighter = highlighted(source)
    assert formatted_at(document, source.index("actual comment")).foreground() == highlighter.fmt_comment.foreground()
    assert formatted_at(document, 0).foreground() != highlighter.fmt_comment.foreground()


def test_incremental_multiline_comment_state_updates_after_edit(highlighted, app):
    document, highlighter = highlighted("/*\nwith size = 2 : (true)\n*/\nrule r { condition: true }")
    assert formatted_at(document, 3).foreground() == highlighter.fmt_comment.foreground()
    cursor = QTextCursor(document)
    cursor.setPosition(2, QTextCursor.MoveMode.KeepAnchor)
    cursor.removeSelectedText()
    app.processEvents()
    assert formatted_at(document, 1).foreground() == highlighter.fmt_logic.foreground()


def test_incomplete_with_keeps_highlighting_and_ast_is_not_required(highlighted):
    source = 'rule r { condition: with value = "http://host" : ('
    document, highlighter = highlighted(source)
    highlighter.rehighlight()
    assert formatted_at(document, source.index("with")).foreground() == highlighter.fmt_logic.foreground()
    assert formatted_at(document, source.index("//")).foreground() == highlighter.fmt_string.foreground()


def test_unicode_offsets_do_not_shift_highlights(highlighted):
    source = 'rule r { meta: value = "😀 //" condition: with size = 1 : (size == 1) }'
    document, highlighter = highlighted(source)
    assert formatted_at(document, source.index("with")).foreground() == highlighter.fmt_logic.foreground()
    assert formatted_at(document, source.index("//")).foreground() == highlighter.fmt_string.foreground()


def test_hex_state_does_not_color_the_entire_rule(highlighted):
    source = 'rule r { strings: $a =\n/* before hex */\n{ 41 // bytes\n42 }\ncondition: $a }'
    document, highlighter = highlighted(source)
    assert formatted_at(document, source.index("41")).foreground() == highlighter.fmt_hexstr.foreground()
    assert formatted_at(document, source.index("bytes")).foreground() == highlighter.fmt_comment.foreground()
    assert formatted_at(document, source.index("condition")).foreground() == highlighter.fmt_section.foreground()
    assert LanguageService().index(source).section(source.index("condition")) == "strings"
    assert LanguageService().index(source).section(len(source)) is None


def test_multiline_metadata_suppresses_completion_even_with_embedded_quotes():
    source = 'rule r { meta: text = """\n"quote" // literal\nwith size'
    assert noncode_at(source, len(source)) is not None
    assert "with size" not in mask_source(source)


def test_comment_stripping_preserves_literal_contents_and_positions():
    stripped = _strip_comments(COMMENT_RULE)
    assert len(stripped) == len(COMMENT_RULE)
    assert stripped.count("\n") == COMMENT_RULE.count("\n")
    assert '"https://example.test/path/*literal*/"' in stripped
    assert "// This is metadata" in stripped
    assert "hex comment" not in stripped


@pytest.mark.parametrize("condition", [
    "with small = filesize : (filesize < 2 or small >= 2)",
    '"filesize < 2" == "filesize < 2"',
    "filesize < 2 or true", "not (filesize < 2)",
    "filesize < 2 + 100",
])
def test_unsupported_size_expressions_never_skip_matching_files(condition):
    source = f"rule safe {{ condition: {condition} }}"
    assert YaraScanner().validate_syntax(source)["valid"]
    assert YaraScanner().compile_rules(source).scan(b"ABCD").matching_rules
    bounds = _compute_bounds_via_regex(source)
    assert bounds.min_size == 0 and bounds.max_size is None


def test_size_prefilter_ignores_fake_rules_and_braces_in_literals():
    source = '''rule real {
        meta: fake = "} rule fake { condition: filesize < 1 } //"
        condition: filesize < 100 /* filesize < 2 */
    }'''
    bounds = _compute_bounds_via_regex(source)
    assert bounds.max_size == 99
    assert _compute_bounds_via_regex(source + '\nrule incomplete { condition:').max_size is None


@pytest.mark.parametrize("condition,expected", [
    ("filesize >= 2 and filesize < 8", (2, 7)),
    ("1 < filesize and (filesize <= 0x10)", (2, 16)),
    ("filesize < 1KB", (0, 1023)),
    ("filesize < 2 or filesize == 8", (0, None)),
    ("with size = filesize : (size == 2)", (0, None)),
])
def test_project_owned_bounds_never_skip_actual_matches(condition, expected):
    source = f"rule r {{ condition: {condition} }}"
    bounds = compute_size_bounds(source)
    assert (bounds.min_size, bounds.max_size) == expected
    rules = yara_x.compile(source)
    for size in [*range(20), 1023, 1024]:
        if rules.scan(b"A" * size).matching_rules:
            assert not bounds.can_skip(size)


def test_large_mode_clears_and_restores_preceding_highlights(highlighted, app, monkeypatch):
    source = 'rule r {\ncondition: true\n}\n'
    document, highlighter = highlighted(source)
    cursor = QTextCursor(document)
    cursor.movePosition(QTextCursor.MoveOperation.End)
    cursor.insertText('// padding\n' * 7000)
    app.processEvents()
    app.processEvents()
    assert not document.firstBlock().layout().formats()
    assert not highlighter._spans
    # Stable plain mode must touch only the edited block, even at the start.
    calls = []
    original = highlighter.highlightBlock
    def record(text):
        calls.append(text)
        original(text)
    monkeypatch.setattr(highlighter, 'highlightBlock', record)
    cursor.setPosition(0)
    cursor.insertText('x')
    app.processEvents()
    assert len(calls) <= 2
    document.undo()
    document.undo()
    app.processEvents()
    app.processEvents()
    assert document.toPlainText() == source
    assert formatted_at(document, 0).foreground() == highlighter.fmt_decl.foreground()
