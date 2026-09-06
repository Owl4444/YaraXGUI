"""Versioned module/type/function catalog generated from official definitions."""
from functools import lru_cache
from importlib.resources import files
import json
import re


@lru_cache(maxsize=1)
def load_catalog():
    return json.loads(files("yarax_editor").joinpath("data/catalog.json").read_text(encoding="utf-8"))


def signature(name, overload):
    params = ", ".join(f"{p['name']}: {p['type']}" for p in overload["parameters"])
    return f"{name}({params}) -> {overload['return_type']}"


class Catalog:
    def __init__(self, available_modules=None):
        self.data = load_catalog()
        self.modules = {k: v for k, v in self.data["modules"].items()
                        if available_modules is None or k in available_modules}
        self.types = dict(self.data["types"])
        self.functions = self.data["functions"]
        self.builtins = self.data["builtins"]
        self.keywords = self.data["keywords"]

    def add_globals(self, globals):
        def describe(value, path):
            if isinstance(value, dict):
                name = "@global:" + path
                self.types[name] = {"fields": {k: {"name": k, "kind": "field", **describe(v, path + "." + k)}
                                               for k, v in value.items()}}
                return {"type": name, "repeated": False}
            if isinstance(value, list):
                return {**describe(value[0] if value else 0, path + "[]"), "repeated": True}
            return {"type": "boolean" if isinstance(value, bool) else "integer" if isinstance(value, int)
                    else "float" if isinstance(value, float) else "string", "repeated": False}
        return {name: self.type_name(describe(value, name)) for name, value in globals.items()}

    @staticmethod
    def type_name(field):
        return ("[]" if field.get("repeated") else "") + field["type"]

    def element(self, field):
        typ = self.types.get(field["type"], {})
        if typ.get("map_entry"):
            return dict(typ["fields"]["value"])
        if field.get("repeated"):
            return {**field, "repeated": False}
        return None

    @staticmethod
    def accessible(field):
        # Hosted-product features cannot be enabled by the public Python compiler.
        return not field.get("unavailable_reason") and not any(a.get("accept_if") for a in field.get("options", {}).get("acl", []))

    def resolve(self, expression, variables=None):
        expression = re.sub(r'\[[^\]]*\]', '[]', expression)
        parts = re.sub(r'\s+', '', expression).split(".")
        first = parts.pop(0)
        first_indexed = first.endswith("[]")
        first = first[:-2] if first_indexed else first
        if first in self.modules:
            current = {"type": self.modules[first]["root"], "kind": "module", "repeated": False}
        elif variables and first in variables:
            typ = variables[first]
            current = {"type": typ.removeprefix("[]"), "kind": "variable", "repeated": typ.startswith("[]")}
        else:
            return None
        if first_indexed:
            current = self.element(current)
            if current is None:
                return None
        for part in parts:
            if current.get("repeated"):
                return None
            typ = self.types.get(current["type"], {})
            if typ.get("map_entry"):
                return None
            indexed = part.endswith("[]")
            name = part[:-2] if indexed else part
            current = typ.get("fields", {}).get(name)
            if current is None or not self.accessible(current):
                return None
            current = dict(current)
            if indexed:
                current = self.element(current)
                if current is None:
                    return None
        return current

    def members(self, expression, variables=None):
        resolved = self.resolve(expression, variables)
        result = {}
        if resolved:
            typ = self.types.get(resolved["type"], {})
            if resolved.get("repeated") or typ.get("map_entry") or resolved["type"] in ("string", "bytes", "RuntimeString"):
                return {"len": {"kind": "function", "documentation": "Number of elements or bytes.",
                    "overloads": [{"parameters": [], "return_type": "integer", "documentation": "Number of elements or bytes."}]}}
            result.update({k: v for k, v in typ.get("fields", {}).items() if self.accessible(v)})
            receiver = resolved["type"] + "."
        else:
            receiver = ""
        for key, overloads in self.functions.items():
            for prefix in (expression + ".", receiver):
                if prefix and key.startswith(prefix) and "." not in key[len(prefix):]:
                    name = key[len(prefix):]
                    result[name] = {"kind": "function", "overloads": overloads,
                        "documentation": "\n\n".join(dict.fromkeys(o["documentation"] for o in overloads)),
                        "source": overloads[0].get("source", "")}
        return result

    def function(self, expression, variables=None):
        if expression in self.builtins:
            return {"kind": "function", "documentation": "Read a number at a byte offset; undefined outside the input.",
                "overloads": [{"parameters": [{"name": "offset", "type": "integer"}],
                               "return_type": "float" if expression.startswith("float") else "integer",
                               "documentation": "Byte offset in the scanned data."}]}
        if "." not in expression:
            return None
        receiver, name = expression.rsplit(".", 1)
        value = self.members(receiver, variables).get(name)
        return value if value and value["kind"] == "function" else None

    def search_docs(self, query, limit=10):
        terms = query.lower().split()
        hits = []
        root = files("yarax_editor").joinpath("data/reference")

        def walk(directory):
            for path in directory.iterdir():
                if path.is_dir():
                    yield from walk(path)
                elif path.name.endswith(".md"):
                    yield path
        for path in walk(root):
            text = path.read_text(encoding="utf-8")
            score = sum(text.lower().count(term) for term in terms)
            if score:
                hits.append({"path": str(path), "score": score, "markdown": text})
        return sorted(hits, key=lambda h: (-h["score"], h["path"]))[:limit]
