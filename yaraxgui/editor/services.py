"""Headless app adapters; language semantics live exclusively in yarax_editor."""
from yarax_editor import Compiler, CompileOptions, FormatRunner
from yarax_editor.lexer import tokenize, comment_spans

format_runner = FormatRunner()
# Preserve the app's existing compiler behavior. The standalone browser keeps
# includes disabled; desktop adapters retain their previous include support. The API supplies its own policy.
APP_COMPILE_OPTIONS = CompileOptions(allow_includes=True)


def validate_source(text, compile_options=APP_COMPILE_OPTIONS):
    result = Compiler(compile_options).validate(text)
    errors = [d.details for d in result.diagnostics if d.severity == "error"]
    warnings = [d.details for d in result.diagnostics if d.severity == "warning"]
    if not result.valid:
        message = "\n".join(d.message for d in result.diagnostics if d.severity == "error")
        return {"valid": False, "message": f"Syntax error: {message}", "error": message,
                "errors": errors, "warnings": warnings}
    rules_info = [{"name": rule.identifier, "tags": list(rule.tags),
                   "strings": len(rule.patterns), "meta": len(rule.metadata),
                   "has_condition": True} for rule in result.rules]
    total_strings = sum(rule["strings"] for rule in rules_info)
    total_tags = sum(len(rule["tags"]) for rule in rules_info)
    return {"valid": True, "rules_count": len(rules_info), "rules_info": rules_info,
            "total_strings": total_strings, "total_tags": total_tags,
            "errors": errors, "warnings": warnings,
            "message": f"Syntax valid: {len(rules_info)} rules, {total_strings} strings, {total_tags} tags"}


def mask_source(text, kinds=("comment", "string", "multiline_string", "regex", "hex")):
    """Keep source coordinates while masking literals for conservative scan bounds."""
    spans = [t.span for t in tokenize(text) if t.kind in kinds]
    if "comment" in kinds:
        spans.extend(comment_spans(text))
    chars = list(text)
    for span in spans:
        for i in range(span.start, span.end):
            if chars[i] not in "\r\n":
                chars[i] = " "
    return "".join(chars)
