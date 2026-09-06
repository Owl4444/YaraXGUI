import pytest
from hypothesis import given, settings, strategies as st
from yarax_editor import Document, DocumentIndex, LanguageService, Span, TextEdit, Compiler, CompileOptions, apply_edits
from yarax_editor.editing import expand_snippet, newline_edit, toggle_line_comments


@pytest.fixture(scope="module")
def service():
    return LanguageService()


def test_hex_comment_highlights_do_not_consume_literal_comment_markers(service):
    text = 'rule r { meta: url = "https://host/*literal*/" strings: $a = {41 /*hex*/ 42 //bytes\n43} condition: $a }'
    highlights = service.highlights(text)
    comments = [text[s.start:s.end] for s, kind in highlights if kind == "comment"]
    assert comments == ["/*hex*/", "//bytes"]
    assert any(text[s.start:s.end] == '"https://host/*literal*/"' and kind == "string" for s, kind in highlights)
    assert all(a.end <= b.start for (a, _), (b, _) in zip(highlights, highlights[1:]))


def labels(service, text, explicit=False):
    offset = text.index("|")
    return {c.label: c for c in service.complete(text.replace("|", ""), offset, explicit=explicit)}


def test_nested_members_and_import_availability(service):
    assert "entry_point" in labels(service, 'import "pe" rule r { condition: pe.en| }')
    assert "raw_data_offset" in labels(service, 'import "pe" rule r { condition: pe.sections[0].raw| }')
    assert "len" in labels(service, 'import "pe" rule r { condition: pe.sections.| }')
    assert "len" in labels(service, 'import "pe" rule r { condition: pe.version_info.| }')
    assert not labels(service, 'rule r { condition: pe.en| }')
    assert "pe" in labels(service, 'import "p|"')
    assert "vba" not in labels(service, 'import "|"')  # Not in this wheel's module_names().


def test_loop_variable_aliases_globals_and_constant_namespaces(service):
    assert "name" in labels(service, 'import "pe" rule r { condition: for any section in pe.sections : (section.na|) }')
    assert "raw_data_offset" in labels(service, 'import "pe" rule r { condition: with sections = pe.sections : (sections[0].raw|) }')
    assert "ITEM_0" in labels(service, 'import "test_proto2" rule r { condition: test_proto2.NestedProto2.NestedEnumeration.ITEM_| }')
    custom = LanguageService(Compiler(CompileOptions(globals={"config": {"threshold": 1, "files": [{"name": "a"}]}})))
    assert "threshold" in labels(custom, 'rule r { condition: config.th| }')
    assert "name" in labels(custom, 'rule r { condition: config.files[0].na| }')
    assert not labels(service, 'import "dex" rule r { condition: dex.stri| }')
    assert not labels(service, 'import "vt" rule r { condition: vt.behav| }')


@pytest.mark.parametrize("source", [
    '// import "p|', '/* import "p|', 'rule r { meta: url = "http://pe.en|',
    'rule r { strings: $a = /pe.en|', 'rule r { strings: $a = { 41 pe.en|',
    'rule r { meta: d = """\n// pe.en|',
])
def test_no_suggestions_inside_noncode(service, source):
    assert not labels(service, source, explicit=True)


def test_exact_match_dismissal_and_middle_of_word_replacement(service):
    assert not labels(service, 'rule r { condition: filesize| }')
    source = 'rule r { condition: file|zz }'
    item = labels(service, source)["filesize"]
    assert apply_edits(source.replace("|", ""), [item.edit]) == 'rule r { condition: filesize }'
    assert "with" in labels(service, 'rule r { condition: with| }', explicit=True)


def test_patterns_and_rule_boundaries(service):
    text = 'rule a { strings: $one = "//" condition: #o| } rule b { condition: true }'
    assert "#one" in labels(service, text)
    assert "$one" not in labels(service, 'rule a { strings: $one = "x" condition: $one } rule b { condition: $o| }')
    assert "a" in labels(service, 'rule a { condition: true } rule b { condition: a| }', explicit=True) or not labels(service, 'rule a { condition: true } rule b { condition: a| }')


def test_with_scope_and_shadowing(service):
    assert "size" in labels(service, 'rule r { condition: with size = filesize : (si| > 0) }')
    assert "size" not in labels(service, 'rule r { condition: (with size = filesize : (size > 0)) and si| }')
    assert "inner" not in labels(service, 'rule r { condition: with outer = 1 : ((with inner = 2 : (inner == 2)) and in|) }')
    assert "i" in labels(service, 'rule r { condition: for all i in (0..1) : (|) }', explicit=True)


def test_signature_help_overloads_and_nested_commas(service):
    text = 'import "pe" rule r { condition: pe.imports("a,b", '
    result = service.signature_help(text, len(text))
    assert result.active_parameter == 1
    assert len(result.signatures) == 8
    text = 'import "math" rule r { condition: math.max(math.min(1, 2), '
    assert service.signature_help(text, len(text)).active_parameter == 1
    text = 'import "pe" rule r { condition: pe.entry_point > 0 }'
    hover = service.hover(text, text.index("entry_point"))
    assert "Entry point" in hover.documentation


def test_definitions_and_folding_ignore_literal_braces(service):
    text = 'rule r {\n strings: $a = "{}"\n condition: $a\n}'
    index = DocumentIndex(text)
    assert index.definitions(text.rindex("$a")) == (Span(text.index("$a"), text.index("$a") + 2),)
    assert len(index.references(text.rindex("$a"))) == 2
    assert len(service.fold_ranges(text)) == 1


@pytest.mark.parametrize("action", ["edit", "move", "dismiss", "close", "undo"])
def test_stale_completion_cannot_reappear(service, action):
    doc = Document('rule r { condition: fil')
    doc.move_cursor(len(doc.text))
    snapshot = doc.snapshot()
    items = service.complete(snapshot.text, snapshot.cursor)
    if action == "edit":
        doc.edit([TextEdit(Span(len(doc.text), len(doc.text)), "e")])
    elif action == "move":
        doc.move_cursor(0)
    elif action == "dismiss":
        doc.dismiss()
    elif action == "close":
        doc.close()
    else:
        doc.edit([TextEdit(Span(0, 0), " ")])
        doc.undo()
    assert not doc.publish_completions(snapshot, items)
    assert not doc.accept(snapshot, items[0])


def test_diagnostics_cleared_on_edit_and_kept_on_cursor_move():
    doc = Document("bad")
    snapshot = doc.snapshot()
    result = Compiler().validate(doc.text)
    doc.move_cursor(1)
    assert doc.publish_diagnostics(snapshot, result.diagnostics)
    doc.edit([TextEdit(Span(0, 3), "rule r { condition: true }")])
    assert not doc.diagnostics
    assert not doc.publish_diagnostics(snapshot, result.diagnostics)


def test_snippets_mirrors_and_atomic_undo(service):
    doc = Document("ru")
    doc.move_cursor(2)
    item = next(c for c in service.complete(doc.text, 2, explicit=True) if c.label == "rule")
    assert doc.accept(doc.snapshot(), item)
    doc.replace_tabstop(2, "test")
    assert "$test =" in doc.text and "$test\n" in doc.text
    assert Compiler().validate(doc.text).valid
    doc.undo()
    assert "$a =" in doc.text
    doc.undo()
    assert doc.text == "ru"
    doc.redo()
    assert "rule rule_name" in doc.text


def test_snippet_choices_escapes_and_invalid_transforms():
    snippet = expand_snippet(r'${1|one,two|} $1 \$literal $0')
    assert snippet.text == 'one one $literal '
    assert len(snippet.tabstops[1]) == 2
    with pytest.raises(ValueError):
        expand_snippet('${1/foo/bar/}')


def test_newline_and_comment_toggle():
    text = "with size = filesize : ()"
    edit, cursor = newline_edit(text, len(text) - 1)
    assert apply_edits(text, [edit]).endswith("(\n    \n)")
    assert cursor == len(text) + 4
    text = '// comment {}'
    edit, _ = newline_edit(text, len(text) - 1)
    assert apply_edits(text, [edit]) == '// comment {\n}'
    text = '  rule r {\n    condition: true\n  }\n'
    commented = apply_edits(text, [toggle_line_comments(text, Span(0, len(text)))])
    assert apply_edits(commented, [toggle_line_comments(commented, Span(0, len(commented)))]) == text


@settings(max_examples=120, deadline=None)
@given(st.text(alphabet='"/*\\\n$[]{}():,abc012😀', max_size=100))
def test_services_tolerate_arbitrary_incomplete_edits(text):
    service = LanguageService()
    service.complete(text, len(text), explicit=True)
    service.signature_help(text, len(text))
    service.fold_ranges(text)
    service.hover(text, len(text) // 2)
