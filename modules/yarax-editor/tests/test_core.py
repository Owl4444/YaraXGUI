from pathlib import Path
import random
import pytest
import yara_x
from hypothesis import given, settings, strategies as st

from yarax_editor import Compiler, CompileOptions, FormatError, FormatOptions, SourceMap, Span, TextEdit, apply_edits, format_source
from yarax_editor.lexer import tokenize, noncode_at
from yarax_editor.formatter import token_identity

DATA = Path(__file__).resolve().parents[1] / "src/yarax_editor/data"
SOURCES = [p for p in sorted((DATA / "corpus").rglob("*")) if p.suffix in (".in", ".yar", ".unformatted")]


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(DATA / "corpus")))
def test_upstream_corpus_lossless_and_compiler_parity(path):
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        # The public API accepts Unicode text; binary input must be rejected at decoding.
        with pytest.raises(UnicodeDecodeError):
            raw.decode("utf-8")
        return
    tokens = tokenize(text)
    assert "".join(t.text for t in tokens) == text
    assert all(t.span.end > t.span.start for t in tokens)
    engine = yara_x.Compiler()
    engine.enable_includes(False)
    try:
        engine.add_source(text)
        original = engine.build()
    except yara_x.CompileError:
        assert not Compiler().validate(text).valid
        with pytest.raises(FormatError):
            format_source(text)
        return
    result = Compiler().validate(text)
    assert result.valid
    formatted = format_source(text)
    assert token_identity(text) == token_identity(formatted)
    assert format_source(formatted) == formatted
    after = yara_x.compile(formatted)
    summary = lambda rules: [(r.identifier, r.tags, r.metadata, tuple(p.identifier for p in r.patterns)) for r in rules]
    assert summary(original) == summary(after)
    # Exercise conditions and patterns, including non-ASCII and embedded nulls.
    for sample in (b"", b"ABCD foo bar\x00\xff", bytes(range(256))):
        assert [r.identifier for r in original.scan(sample).matching_rules] == [r.identifier for r in after.scan(sample).matching_rules]


@settings(max_examples=300, deadline=None)
@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=300))
def test_arbitrary_incomplete_unicode_is_lossless(text):
    tokens = tokenize(text)
    assert "".join(t.text for t in tokens) == text
    assert [t.span.start for t in tokens] == [0] + [t.span.end for t in tokens[:-1]] if tokens else text == ""
    noncode_at(text, len(text))


@pytest.mark.parametrize("literal", [
    '"http://host/*literal*/"', r'"a\"//b"', r'/https?:\/\/host\/a/is',
    '"""\n// metadata\n/* still metadata */\n"""',
    '{ 41 ~?0 [1-3] (42 | 43) /* } fake closing */ 44 }',
])
def test_literal_contents_not_reinterpreted(literal):
    source = "$a = " + literal + " // real comment"
    tokens = [t for t in tokenize(source) if t.kind != "whitespace"]
    assert tokens[2].text == literal
    assert tokens[3].kind == "comment"
    assert noncode_at(source, source.index("real comment")) is not None


@pytest.mark.parametrize("literal", ["0o755", "1_000_000", "0xFF_FF", "1_000.5", "2KB", "4MB"])
def test_numeric_syntax_is_a_single_token(literal):
    assert len(tokenize(literal)) == 1
    assert tokenize(literal)[0].kind == "number"


def test_positions_with_non_bmp_crlf_and_utf8_diagnostics():
    text = 'rule r { meta: text = "😀"\r\n condition: missing }'
    mapping = SourceMap(text)
    for offset in range(len(text) + 1):
        position = mapping.position(offset)
        if text[offset:offset + 1] == "\n":
            continue
        assert mapping.offset(**position) == offset
        assert mapping.byte_offset(len(text[:offset].encode())) == offset
    result = Compiler().validate(text)
    diagnostic = next(d for d in result.diagnostics if d.severity == "error")
    assert text[diagnostic.span.start:diagnostic.span.end] == "missing"
    emoji = text.index("😀")
    p = mapping.position(emoji)
    with pytest.raises(ValueError):
        mapping.offset(p["line"], p["character"] + 1)


def test_globals_and_includes(tmp_path):
    (tmp_path / "common.yar").write_text("rule helper { condition: true }")
    source = 'include "common.yar" rule r { condition: helper and threshold > 1 }'
    options = CompileOptions(globals={"threshold": 2}, allow_includes=True, include_dirs=(str(tmp_path),))
    compiler = Compiler(options)
    assert compiler.validate(source).valid
    assert compiler.validate(format_source(source, compiler=compiler)).valid
    assert not Compiler().validate(source).valid


def test_included_diagnostics_do_not_point_into_current_editor(tmp_path):
    (tmp_path / "bad.yar").write_text("rule bad { condition: missing }")
    result = Compiler(CompileOptions(allow_includes=True, include_dirs=(str(tmp_path),))).validate('include "bad.yar"')
    assert not result.valid
    assert all(d.span is None for d in result.diagnostics if d.origin and "bad.yar" in d.origin)


@pytest.mark.parametrize("condition", [
    "with a = filesize : (a == 2)",
    "with a = uint8(0), b = uint8(1) : (a == 65 and b == 66)",
    "with a = filesize : (with b = a + 1 : (b == 3))",
    "for all i in (0..1) : (with v = uint8(i) : (v >= 65))",
    'with text = "ABC" : (text.len() == 3)',
    "1_000 == 0x3_E8 and 0o10 == 8 and 1.5 + 0.5 == 2.0",
])
def test_modern_yarax_expressions(condition):
    source = f"rule r {{ condition: {condition} }}"
    result = format_source(source)
    assert yara_x.compile(result).scan(b"AB").matching_rules


def test_format_crlf_and_comment_directives():
    source = '// rule-level comment\nrule r { condition: true }'
    formatted = format_source(source, options=FormatOptions(indent="\t", newline="\r\n"))
    assert "\r\n\tcondition:" in formatted
    assert format_source(formatted, options=FormatOptions(indent="\t", newline="\r\n")) == formatted


def test_edits_reject_overlap_and_preserve_order():
    assert apply_edits("abcdef", [TextEdit(Span(4, 6), "!"), TextEdit(Span(0, 1), "AB")]) == "ABbcd!"
    with pytest.raises(ValueError):
        apply_edits("abc", [TextEdit(Span(0, 2), "x"), TextEdit(Span(1, 3), "y")])


CONDITIONS = st.recursive(
    st.integers(0, 500).map(lambda n: f"filesize >= {n}"),
    lambda child: st.tuples(child, st.sampled_from(["and", "or"]), child).map(lambda x: f"({x[0]} {x[1]} {x[2]})"),
    max_leaves=10,
)


@settings(max_examples=100, deadline=None)
@given(CONDITIONS, st.binary(max_size=512))
def test_generated_boolean_trees_format_and_match_identically(condition, sample):
    text = 'rule r { meta: marker = "// /* literal */" condition: ' + condition + ' }'
    formatted = format_source(text)
    assert format_source(formatted) == formatted
    assert token_identity(text) == token_identity(formatted)
    assert bool(yara_x.compile(text).scan(sample).matching_rules) == bool(yara_x.compile(formatted).scan(sample).matching_rules)


def test_compiler_errors_are_destroyed_on_the_worker_thread(monkeypatch):
    import gc
    import sys
    from concurrent.futures import ThreadPoolExecutor
    errors = []
    monkeypatch.setattr(sys, "unraisablehook", lambda error: errors.append(str(error.exc_value)))
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: Compiler().validate("rule r { condition: missing }"), range(30)))
    assert all(not result.valid for result in results)
    gc.collect()
    assert not errors
