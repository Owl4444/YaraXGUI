import hashlib
import json
from pathlib import Path
import pytest
import yara_x
from yarax_editor.catalog import Catalog, load_catalog
from yarax_editor import Compiler, LanguageService

DATA = Path(__file__).resolve().parents[1] / "src/yarax_editor/data"
CATALOG = Catalog(yara_x.module_names())
TYPE_PATHS = {}


def field_cases():
    seen = set()
    output = []
    def visit(module, expression, typ, restricted=False):
        if (module, typ) in seen:
            return
        seen.add((module, typ))
        TYPE_PATHS[(module, typ)] = (expression, restricted)
        for name, field in CATALOG.types.get(typ, {}).get("fields", {}).items():
            field = dict(field)
            field["restricted"] = bool(restricted or field.get("unavailable_reason") or any(a.get("accept_if") for a in field.get("options", {}).get("acl", [])))
            path = expression + "." + name
            output.append((module, path, field))
            nested = CATALOG.types.get(field["type"], {})
            if nested.get("map_entry"):
                key_type = nested["fields"]["key"]["type"]
                key = '"test"' if key_type in ("string", "bytes") else "0"
                visit(module, path + "[" + key + "]", nested["fields"]["value"]["type"], field["restricted"])
            elif field.get("repeated"):
                visit(module, path + "[0]", field["type"], field["restricted"])
            elif not nested.get("enum"):
                visit(module, path, field["type"], field["restricted"])
    for module, info in CATALOG.modules.items():
        visit(module, module, info["root"])
    return output


FIELDS = field_cases()


@pytest.mark.parametrize("module,path,field", FIELDS, ids=[p for _, p, _ in FIELDS])
def test_catalog_field_paths_against_compiler(module, path, field):
    # Enum containers are namespaces, not expression values.
    if field["kind"] == "enum":
        for name in CATALOG.types[field["type"]]["fields"]:
            result = Compiler().validate(f'import "{module}" rule r {{ condition: defined {path}.{name} }}')
            assert result.valid != field["restricted"], result.diagnostics
        return
    source = f'import "{module}" rule r {{ condition: with _probe = {path} : (true) }}'
    if field["restricted"]:
        assert not Compiler().validate(source).valid
    else:
        yara_x.compile(source)


FUNCTIONS = [(name, overload) for name, overloads in CATALOG.functions.items()
             for overload in overloads if overload["module"] in CATALOG.modules and not overload["method_of"]]


@pytest.mark.parametrize("name,overload", FUNCTIONS, ids=[n + str(len(o["parameters"])) for n, o in FUNCTIONS])
def test_every_exported_function_overload_compiles(name, overload):
    def argument(typ):
        if "RegexId" in typ:
            return "/test/"
        if "String" in typ:
            return '"test"'
        if typ == "bool":
            return "true"
        if typ in ("f32", "f64"):
            return "1.0"
        return "1"
    args = ", ".join(argument(p["type"]) for p in overload["parameters"])
    yara_x.compile(f'import "{overload["module"]}" rule r {{ condition: defined {name}({args}) }}')


METHODS = [(name, overload) for name, overloads in CATALOG.functions.items()
           for overload in overloads if overload["module"] in CATALOG.modules and overload["method_of"]]


@pytest.mark.parametrize("name,overload", METHODS, ids=[n + str(len(o["parameters"])) for n, o in METHODS])
def test_exported_methods_use_receiver_types(name, overload):
    receiver, restricted = TYPE_PATHS[(overload["module"], overload["method_of"])]
    args = ", ".join('"test"' if "String" in p["type"] else "1" for p in overload["parameters"])
    expression = receiver + "." + overload["name"] + "(" + args + ")"
    result = Compiler().validate(f'import "{overload["module"]}" rule r {{ condition: defined {expression} }}')
    assert result.valid != restricted, result.diagnostics
    if not restricted:
        assert overload["name"] in CATALOG.members(receiver)


@pytest.mark.parametrize("name", CATALOG.builtins)
def test_every_builtin_is_real(name):
    yara_x.compile(f"rule r {{ condition: defined {name}(0) }}")


def test_catalog_generation_and_reference_integrity():
    manifest = json.loads((DATA / "manifest.json").read_text())
    assert manifest["version"] == "1.20.0"
    assert manifest["export_count"] == sum(map(len, load_catalog()["functions"].values()))
    assert hashlib.sha256((DATA / "catalog.json").read_bytes()).hexdigest() == manifest["catalog_sha256"]
    for entry in manifest["files"]:
        assert hashlib.sha256((DATA / entry["path"]).read_bytes()).hexdigest() == entry["sha256"]
    assert set(yara_x.module_names()) <= load_catalog()["modules"].keys()
    assert "uint64" not in CATALOG.builtins
    assert len(CATALOG.keywords) == 40
    assert len(FIELDS) > 600


def test_offline_docs_and_deprecations():
    assert CATALOG.search_docs("with statement")
    text = 'import "pe" rule r { condition: pe.number_of_sect'
    items = LanguageService().complete(text, len(text))
    assert items and items[0].deprecated
