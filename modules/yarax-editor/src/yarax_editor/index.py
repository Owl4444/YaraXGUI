"""Tolerant document structure and scoped declarations for incomplete edits."""
import re
from .lexer import significant
from .model import Span, Symbol


class DocumentIndex:
    def __init__(self, text, catalog=None):
        self.text = text
        self.tokens = significant(text)
        self.catalog = catalog
        self.pairs = {}
        stack = []
        for i, token in enumerate(self.tokens):
            if token.text in ("{", "(", "["):
                stack.append(i)
            elif token.text in ("}", ")", "]") and stack:
                opener = stack[-1]
                if {"{": "}", "(": ")", "[": "]"}[self.tokens[opener].text] == token.text:
                    stack.pop()
                    self.pairs[opener] = i
        self.imports = {}
        self.symbols = []
        self.rules = []
        tokens = self.tokens
        for i, token in enumerate(tokens[:-1]):
            if token.text == "import" and tokens[i + 1].kind == "string":
                name = tokens[i + 1].text.strip('"')
                self.imports[name] = tokens[i + 1].span
            if token.text != "rule" or tokens[i + 1].kind != "identifier":
                continue
            opening = next((j for j in range(i + 2, len(tokens)) if tokens[j].text in ("{", "rule")), None)
            if opening is None or tokens[opening].text != "{":
                continue
            closing = self.pairs.get(opening, len(tokens))
            end = tokens[closing].span.end if closing < len(tokens) else len(text) + 1
            scope = Span(tokens[opening].span.end, end)
            self.rules.append((opening, closing, scope))
            self.symbols.append(Symbol(tokens[i + 1].text, "rule", tokens[i + 1].span, Span(end, len(text) + 1), "boolean"))
            section = None
            for j in range(opening + 1, closing):
                current = tokens[j]
                following = tokens[j + 1].text if j + 1 < len(tokens) else ""
                if current.text in ("meta", "strings", "condition") and following == ":":
                    section = current.text
                if section == "strings" and current.kind == "reference" and current.text.startswith("$") and following == "=":
                    if len(current.text) > 1:
                        self.symbols.append(Symbol(current.text, "pattern", current.span, scope, "pattern"))
            self._bindings(opening, closing, scope)

    def _bindings(self, opening, closing, rule_scope):
        tokens = self.tokens
        for i in range(opening + 1, closing):
            if tokens[i].text not in ("with", "for"):
                continue
            j = i + 1
            candidates = []
            while j < closing and tokens[j].text != ":":
                if tokens[i].text == "with" and tokens[j].kind == "identifier" and j + 1 < closing and tokens[j + 1].text == "=":
                    name = tokens[j]
                    value_start = j + 2
                    j = value_start
                    while j < closing and tokens[j].text not in (",", ":"):
                        if j in self.pairs:
                            j = self.pairs[j] + 1
                        else:
                            j += 1
                    expr = self.text[tokens[value_start].span.start:tokens[j].span.start] if value_start < j else ""
                    typ = self._infer_type(expr)
                    candidates.append((name, tokens[j].span.end if j < closing else len(self.text), typ))
                elif tokens[i].text == "for" and tokens[j].text == "in":
                    # Quantifier precedes one (array/range) or two (map) names.
                    names = [t for t in tokens[i + 2:j] if t.kind == "identifier"]
                    iterable_end = next((k for k in range(j + 1, closing) if tokens[k].text == ":"), closing)
                    expression = self.text[tokens[j + 1].span.start:tokens[iterable_end].span.start] if j + 1 < iterable_end < len(tokens) else ""
                    variables = {s.name: s.type for s in self.symbols if s.kind == "variable" and s.scope.contains(tokens[j].span.start)}
                    resolved = self.catalog.resolve(expression, variables) if self.catalog else None
                    typ = self.catalog.types.get(resolved["type"], {}) if resolved else {}
                    if resolved and typ.get("map_entry") and len(names) == 2:
                        inferred = [typ["fields"]["key"]["type"], typ["fields"]["value"]["type"]]
                    elif resolved and resolved.get("repeated") and len(names) == 1:
                        inferred = [resolved["type"]]
                    else:
                        inferred = ["integer"] * len(names)
                    candidates.extend((t, -1, inferred[n]) for n, t in enumerate(names))
                    j += 1
                elif j in self.pairs:
                    j = self.pairs[j] + 1
                else:
                    j += 1
            if j + 1 >= closing or tokens[j + 1].text != "(":
                continue
            body = j + 1
            end_index = self.pairs.get(body)
            end = tokens[end_index].span.end if end_index is not None else rule_scope.end
            for name, visible, typ in candidates:
                visible = tokens[body].span.end if visible < 0 else visible
                self.symbols.append(Symbol(name.text, "variable", name.span, Span(visible, end), typ))

    def _infer_type(self, expr):
        expr = expr.strip()
        if expr.startswith('"'):
            return "string"
        if self.catalog:
            resolved = self.catalog.resolve(expr)
            if resolved:
                return self.catalog.type_name(resolved)
        if re.match(r"(?:float\d|\d+\.\d)", expr):
            return "float"
        return "integer"

    def visible(self, offset):
        symbols = {}
        for symbol in self.symbols:
            if symbol.scope.contains(offset):
                symbols[symbol.name] = symbol
        return symbols

    def section(self, offset):
        for opening, closing, scope in self.rules:
            if scope.contains(offset):
                section = None
                for i in range(opening + 1, closing):
                    token = self.tokens[i]
                    if token.span.start >= offset:
                        break
                    if (token.text in ("meta", "strings", "condition") and i + 1 < len(self.tokens)
                            and self.tokens[i + 1].text == ":"):
                        section = token.text
                return section
        return None

    def definitions(self, offset):
        token = next((t for t in self.tokens if t.span.contains(offset)), None)
        if token is None:
            return ()
        declaration = next((s for s in self.symbols if s.declaration == token.span), None)
        if declaration:
            return (declaration.declaration,)
        name = "$" + token.text[1:] if token.kind == "reference" else token.text
        symbol = self.visible(offset).get(name)
        return (symbol.declaration,) if symbol else ()

    def references(self, offset):
        declarations = self.definitions(offset)
        if not declarations:
            return ()
        return tuple(t.span for t in self.tokens if self.definitions(t.span.start) == declarations)
