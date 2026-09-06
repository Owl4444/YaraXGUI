"""Stateless editor features; completions are explicit, replaceable text edits."""
import re
from functools import lru_cache
from .catalog import Catalog, signature
from .compiler import Compiler
from .index import DocumentIndex
from .lexer import noncode_at, significant, tokenize, comment_spans
from .model import Completion, Hover, SignatureHelp, Span, TextEdit


SNIPPETS = {
    "rule": "rule ${1:rule_name} {\n    strings:\n        $${2:a} = \"${3:text}\"\n    condition:\n        $${2:a}\n}\n$0",
    "with": "with ${1:value} = ${2:filesize} : (${3:value > 0})$0",
    "for": "for ${1:all} ${2:i} in (${3:0}..${4:10}) : (${5:uint8(i) == 0})$0",
    "any of": "any of (${1:$a*})$0",
    "all of": "all of (${1:$a*})$0",
    "import": 'import "${1:pe}"$0',
}
CONDITION = set("and or not all any none them for of in at with defined true false contains icontains matches startswith endswith istartswith iendswith iequals filesize entrypoint".split())
MODIFIERS = set("ascii wide nocase fullword xor base64 base64wide".split())
EXPRESSION = re.compile(r'[A-Za-z_]\w*(?:\s*\[[^\]\n]*\])?(?:\s*\.\s*[A-Za-z_]\w*(?:\s*\[[^\]\n]*\])?)*$')


class LanguageService:
    def __init__(self, compiler=None):
        self.compiler = compiler or Compiler()
        self.catalog = Catalog(self.compiler.modules)
        self.globals = self.catalog.add_globals(self.compiler.options.globals)

    @lru_cache(maxsize=8)
    def index(self, text):
        return DocumentIndex(text, self.catalog)

    def complete(self, text, offset, *, explicit=False):
        if not 0 <= offset <= len(text):
            raise ValueError("Offset outside document")
        prefix_text = text[:offset]
        noncode = noncode_at(text, offset)
        tokens = tuple(t for t in significant(text) if t.span.start < offset)
        # Only the literal immediately following an actual import gets suggestions.
        quoted_import = (noncode is not None and noncode.kind == "string" and len(tokens) >= 2
                         and tokens[-2].text == "import")
        if noncode and not quoted_import:
            return ()
        match = re.search(r'[$#@!]?[A-Za-z_0-9]*$', prefix_text)
        prefix = match.group() if match else ""
        start = offset - len(prefix)
        suffix = re.match(r'[A-Za-z_0-9]*', text[offset:]).group()
        span = Span(start, offset + len(suffix))
        index = self.index(text)
        visible = index.visible(offset)
        variables = {**self.globals, **{name: s.type for name, s in visible.items() if s.kind == "variable"}}
        candidates = {}
        if quoted_import or (tokens and tokens[-1].text == "import" and not prefix):
            for name, info in self.catalog.modules.items():
                value = name if quoted_import else f'"{name}"'
                candidates[name] = Completion(name, "module", TextEdit(span, value), documentation=f"YARA-X {name} module", source=info["source"])
        else:
            before_word = text[:start].rstrip()
            receiver = None
            if before_word.endswith("."):
                match = EXPRESSION.search(before_word[:-1])
                receiver = match.group() if match else ""
            if receiver is not None:
                root = receiver.split(".", 1)[0].split("[", 1)[0]
                if root not in index.imports and root not in variables:
                    return ()
                for name, info in self.catalog.members(receiver, variables).items():
                    overloads = info.get("overloads", [])
                    detail = "\n".join(signature(name, o) for o in overloads) if overloads else info.get("type", "")
                    deprecated = bool(info.get("options", {}).get("deprecation_notice"))
                    # Plain insertion never adds a second set of parentheses.
                    value = name + ("()" if overloads and not text[span.end:].lstrip().startswith("(") else "")
                    candidates[name] = Completion(name, info["kind"], TextEdit(span, value), detail,
                        info.get("documentation", ""), info.get("source", ""), deprecated)
            else:
                section = index.section(offset)
                keywords = CONDITION if section == "condition" else MODIFIERS if section == "strings" else {"true", "false"} if section == "meta" else {"rule", "private", "global", "import", "include", "meta", "strings", "condition"}
                for name in keywords:
                    candidates[name] = Completion(name, "keyword", TextEdit(span, name))
                if section == "condition":
                    for name in self.catalog.builtins:
                        fn = self.catalog.function(name)
                        value = name if text[span.end:].lstrip().startswith("(") else name + "()"
                        candidates[name] = Completion(name, "function", TextEdit(span, value), signature(name, fn["overloads"][0]), fn["documentation"])
                    for name in index.imports:
                        candidates[name] = Completion(name, "module", TextEdit(span, name), documentation=f"Imported {name} module")
                    for name, symbol in visible.items():
                        label = prefix[0] + name[1:] if symbol.kind == "pattern" and prefix[:1] in ("$", "#", "@", "!") else name
                        candidates[label] = Completion(label, symbol.kind, TextEdit(span, label), symbol.type)
                    for name in self.compiler.options.globals:
                        candidates[name] = Completion(name, "variable", TextEdit(span, name), "external global")
                if explicit:
                    for name, value in SNIPPETS.items():
                        if name in keywords or (section == "condition" and name in ("any of", "all of")):
                            candidates[name] = Completion(name, "snippet", TextEdit(span, value), snippet=True)
        # An exact automatic match closes the popup, even if longer variants exist.
        if not explicit and prefix in candidates:
            return ()
        if not explicit and not prefix and not quoted_import and not text[:start].rstrip().endswith("."):
            return ()
        return tuple(sorted((c for label, c in candidates.items() if label.startswith(prefix)
                            and (c.edit.text != text[c.edit.span.start:c.edit.span.end] or c.snippet)),
                            key=lambda c: (c.deprecated, len(c.label), c.label)))

    def signature_help(self, text, offset):
        tokens = tuple(t for t in significant(text) if t.span.start < offset)
        stack = []
        for i, token in enumerate(tokens):
            if token.text in ("(", "["):
                stack.append([i, 0])
            elif token.text in (")", "]") and stack:
                stack.pop()
            elif token.text == "," and stack:
                stack[-1][1] += 1
        index = self.index(text)
        variables = {**self.globals, **{name: s.type for name, s in index.visible(offset).items() if s.kind == "variable"}}
        for opening, parameter in reversed(stack):
            if tokens[opening].text != "(":
                continue
            match = EXPRESSION.search(text[:tokens[opening].span.start].rstrip())
            if not match:
                continue
            name = re.sub(r'\s+', '', match.group())
            fn = self.catalog.function(name, variables)
            if fn:
                return SignatureHelp(tuple(signature(name, o) for o in fn["overloads"]), parameter,
                                     tuple(o.get("documentation", "") for o in fn["overloads"]))
        return None

    def hover(self, text, offset):
        token = next((t for t in significant(text) if t.span.contains(offset)), None)
        if not token or token.kind not in ("identifier", "reference"):
            return None
        match = EXPRESSION.search(text[:token.span.end])
        name = re.sub(r'\s+', '', match.group()) if match else token.text
        index = self.index(text)
        visible = index.visible(offset)
        variables = {**self.globals, **{name: s.type for name, s in visible.items() if s.kind == "variable"}}
        fn = self.catalog.function(name, variables)
        if fn:
            return Hover(token.span, "\n".join(signature(name, o) for o in fn["overloads"]), fn["documentation"], fn.get("source", ""))
        if "." in name:
            receiver, member = name.rsplit(".", 1)
            info = self.catalog.members(receiver, variables).get(member)
            if info:
                return Hover(token.span, f"{name}: {info.get('type', '')}", info.get("documentation", ""), info.get("source", ""))
        key = "$" + token.text[1:] if token.kind == "reference" else token.text
        if key in visible:
            s = visible[key]
            return Hover(token.span, f"{s.name}: {s.type}", f"{s.kind.capitalize()} declared at offset {s.declaration.start}.")
        return None

    def highlights(self, text):
        comments = iter(comment_spans(text))
        comment = next(comments, None)
        result = []
        for token in tokenize(text):
            if token.kind == "whitespace":
                continue
            while comment is not None and comment.end <= token.span.start:
                comment = next(comments, None)
            if token.kind == "hex":
                start = token.span.start
                while comment is not None and comment.start < token.span.end:
                    if start < comment.start:
                        result.append((Span(start, comment.start), "hex"))
                    result.append((comment, "comment"))
                    start = comment.end
                    comment = next(comments, None)
                if start < token.span.end:
                    result.append((Span(start, token.span.end), "hex"))
            else:
                result.append((token.span, "keyword" if token.kind == "identifier"
                    and token.text in self.catalog.keywords else token.kind))
        return tuple(result)

    def fold_ranges(self, text):
        index = self.index(text)
        ranges = [Span(index.tokens[i].span.start, index.tokens[j].span.end) for i, j in index.pairs.items()
                  if "\n" in text[index.tokens[i].span.start:index.tokens[j].span.end]]
        ranges.extend(t.span for t in tokenize(text) if t.kind in ("comment", "hex", "multiline_string") and "\n" in t.text)
        return tuple(sorted(ranges, key=lambda s: (s.start, -s.end)))
