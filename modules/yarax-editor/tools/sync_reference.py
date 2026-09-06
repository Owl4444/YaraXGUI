"""Generate offline references/catalog from the exact official source release.

Usage: python tools/sync_reference.py /path/to/yara-x-checkout
Requires the `reference` development extra. No network or runtime generation.
"""
import hashlib
import importlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

VERSION = "1.20.0"
COMMIT = "60ad06971467029e77967e59d580cbbe85a1474d"
ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src/yarax_editor/data"


def main(upstream):
    import grpc_tools
    from google.protobuf import descriptor_pb2 as pb
    from google.protobuf.json_format import MessageToDict
    upstream = Path(upstream).resolve()
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=upstream, text=True).strip()
    if actual != COMMIT:
        raise ValueError(f"Expected {COMMIT}, received {actual}; update compatibility tests first")
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--", "site/content/docs", "parser/src", "lib/src/modules", "lib/src/wasm", "fmt/src/testdata"], cwd=upstream, check=True, capture_output=True)
    DATA.mkdir(parents=True, exist_ok=True)
    manifest = {"version": VERSION, "commit": COMMIT, "repository": "https://github.com/VirusTotal/yara-x", "files": []}

    def copy(source, target):
        relative = source.relative_to(upstream).as_posix()
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        manifest["files"].append({"path": target.relative_to(DATA).as_posix(),
            "source": f"https://github.com/VirusTotal/yara-x/blob/{COMMIT}/{relative}",
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest()})

    copy(upstream / "LICENSE", DATA / "UPSTREAM-LICENSE")
    for path in sorted((upstream / "site/content/docs").rglob("*.md")):
        copy(path, DATA / "reference" / path.relative_to(upstream / "site/content/docs"))
    proto_root = upstream / "lib/src/modules/protos"
    for path in sorted(proto_root.rglob("*.proto")):
        copy(path, DATA / "protos" / path.relative_to(proto_root))
    for name in ("mod.rs", "tokens.rs"):
        copy(upstream / "parser/src/tokenizer" / name, DATA / "grammar" / name)
    for path in sorted((upstream / "parser/src/parser").glob("*.rs")):
        copy(path, DATA / "grammar/parser" / path.name)
    copy(upstream / "lib/src/types/structure.rs", DATA / "grammar/module_structure.rs")
    for area, source in (("parser", upstream / "parser/src/parser/tests/testdata"),
                         ("compiler", upstream / "lib/src/compiler/tests/testdata"),
                         ("formatter", upstream / "fmt/src/testdata")):
        if source.exists():
            for path in sorted(source.rglob("*")):
                if path.suffix in (".in", ".yar", ".out", ".unformatted", ".formatted") and path.stat().st_size < 200_000:
                    copy(path, DATA / "corpus" / area / path.relative_to(source))

    with tempfile.TemporaryDirectory() as tmp:
        args = [sys.executable, "-m", "grpc_tools.protoc", f"-I{proto_root}",
                f"-I{Path(grpc_tools.__file__).parent / '_proto'}", f"--python_out={tmp}",
                f"--descriptor_set_out={tmp}/modules.pb", "--include_imports", "--include_source_info"]
        args += [str(p) for p in sorted(proto_root.rglob("*.proto"))]
        subprocess.run(args, check=True, capture_output=True)
        sys.path.insert(0, tmp)
        opts = importlib.import_module("yara_pb2")
        descriptors = pb.FileDescriptorSet.FromString(Path(tmp, "modules.pb").read_bytes())

    catalog = {"version": VERSION, "commit": COMMIT, "modules": {}, "types": {}, "functions": {}, "keywords": []}
    all_messages = {}
    enums = []
    for file in descriptors.file:
        if file.name.startswith("google/"):
            continue
        comments = {tuple(l.path): l.leading_comments.strip() for l in file.source_code_info.location}
        source = f"https://github.com/VirusTotal/yara-x/blob/{COMMIT}/lib/src/modules/protos/{file.name}"
        module_options = file.options.Extensions[opts.module_options]
        if module_options.name:
            catalog["modules"][module_options.name] = {"root": module_options.root_message,
                "feature": module_options.cargo_feature, "source": source}

        def add_messages(messages, parent, prefix):
            for i, message in enumerate(messages):
                name = f"{parent}.{message.name}"
                path = prefix + (i,)
                all_messages[name] = message
                fields = {}
                for j, field in enumerate(message.field):
                    option = field.options.Extensions[opts.field_options]
                    if option.ignore:
                        continue
                    label = option.name or field.name
                    scalar = pb.FieldDescriptorProto.Type.Name(field.type).removeprefix("TYPE_").lower()
                    typ = field.type_name.lstrip(".") or scalar
                    fields[label] = {"name": label, "type": typ,
                        "repeated": field.label == pb.FieldDescriptorProto.LABEL_REPEATED,
                        "kind": "field", "documentation": comments.get(path + (2, j), ""),
                        "source": source, "options": MessageToDict(option, preserving_proto_field_name=True)}
                catalog["types"][name] = {"fields": fields, "map_entry": message.options.map_entry,
                                          "documentation": comments.get(path, "")}
                add_messages(message.nested_type, name, path + (3,))
                for j, enum in enumerate(message.enum_type):
                    enums.append((enum, name, comments, path + (4, j), source, module_options.name))
        add_messages(file.message_type, file.package, (4,))
        for i, enum in enumerate(file.enum_type):
            enums.append((enum, file.package, comments, (5, i), source, module_options.name))

    enum_definitions = {}
    for enum, parent, comments, path, source, module in enums:
        options = enum.options.Extensions[opts.enum_options]
        fields = {}
        for i, value in enumerate(enum.value):
            override = value.options.Extensions[opts.enum_value]
            which = override.WhichOneof("value")
            actual_value = getattr(override, which) if which else value.number
            fields[value.name] = {"name": value.name, "kind": "constant", "type": "float" if which == "f64" else "integer",
                "documentation": comments.get(path + (2, i), ""), "source": source,
                "value": actual_value, "repeated": False}
        full_name = f"{parent}.{enum.name}"
        catalog["types"][full_name] = {"fields": fields, "map_entry": False, "enum": True}
        enum_definitions[full_name] = (parent, options.name or enum.name, options.inline, fields, source, module)

    # Enum constants live in namespaces beneath the module root, not under
    # instances of protobuf messages. Mirror Struct::nested_enums/add_enum_fields.
    for module, info in catalog["modules"].items():
        reachable, visited = set(), set()
        def collect(typ):
            if typ in visited:
                return
            visited.add(typ)
            if typ in enum_definitions:
                reachable.add(typ)
                return
            for name, definition in enum_definitions.items():
                if definition[0] == typ:
                    reachable.add(name)
            for field in catalog["types"].get(typ, {}).get("fields", {}).values():
                if not catalog["types"].get(field["type"], {}).get("map_entry"):
                    collect(field["type"])
        collect(info["root"])
        reachable.update(name for name, d in enum_definitions.items() if d[5] == module and d[0] not in all_messages)
        for name in sorted(reachable):
            parent, enum_name, inline, fields, source, _ = enum_definitions[name]
            parts = [] if inline else [enum_name]
            while parent in all_messages:
                if parent != info["root"]:
                    message = all_messages[parent]
                    parts.append(message.options.Extensions[opts.message_options].name or message.name)
                parent = parent.rsplit(".", 1)[0]
            owner = info["root"]
            for part in reversed(parts):
                namespace = owner + ".@" + part
                catalog["types"].setdefault(namespace, {"fields": {}, "map_entry": False})
                catalog["types"][owner]["fields"][part] = {"name": part, "kind": "namespace",
                    "type": namespace, "repeated": False, "source": source, "documentation": "Constant namespace"}
                owner = namespace
            catalog["types"][owner]["fields"].update(fields)

    # Export annotations are authoritative for aliases, overloads and methods.
    modules_dir = upstream / "lib/src/modules"
    attr = re.compile(r'^#\[module_export(?:\((.*?)\))?\]', re.M | re.S)
    signature = re.compile(r'\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\((.*?)\)\s*(?:->\s*([^\{]+))?\{', re.S)
    exports = 0
    for file in sorted(modules_dir.rglob("*.rs")):
        text = file.read_text()
        module = file.relative_to(modules_dir).parts[0].removesuffix(".rs")
        for match in attr.finditer(text):
            fn = signature.match(text, match.end())
            if not fn:
                raise ValueError(f"Unrecognized export: {file}:{match.start()}")
            attrs = dict(re.findall(r'(\w+)\s*=\s*"([^"]+)"', match.group(1) or ""))
            exported = attrs.get("name", fn[1])
            method_of = attrs.get("method_of")
            params = []
            for param in fn[2].split(","):
                if ":" not in param:
                    continue
                name, typ = param.split(":", 1)
                if "ScanContext" not in typ:
                    params.append({"name": name.strip(), "type": typ.strip()})
            if method_of:
                params = params[1:]  # The first non-context argument is the receiver.
            before = text[:match.start()].rstrip().splitlines()
            doc = []
            for line in reversed(before):
                if not line.startswith("///"):
                    break
                doc.append(line.removeprefix("///").lstrip())
            key = f"{method_of or module}.{exported}"
            catalog["functions"].setdefault(key, []).append({"name": exported.split(".")[-1],
                "module": module, "method_of": method_of, "parameters": params,
                "return_type": (fn[3] or "()").strip(), "documentation": "\n".join(reversed(doc)),
                "source": f"https://github.com/VirusTotal/yara-x/blob/{COMMIT}/{file.relative_to(upstream).as_posix()}#L{text.count(chr(10), 0, match.start()) + 1}"})
            exports += 1
    tokens = (upstream / "parser/src/tokenizer/tokens.rs").read_text()
    catalog["keywords"] = sorted(set(m.lower() for m in re.findall(r'^    (\w+)_KW,', tokens, re.M)))
    wasm = upstream / "lib/src/wasm/mod.rs"
    copy(wasm, DATA / "grammar/builtins.rs")
    catalog["builtins"] = sorted(set(re.findall(r'^gen_(?:int|float)_fn!\((\w+),', wasm.read_text(), re.M)))
    for typ in catalog["types"].values():
        for field in typ["fields"].values():
            if field["name"] in catalog["keywords"]:
                field["unavailable_reason"] = "Reserved identifier in the YARA-X 1.20.0 parser"
    manifest["export_count"] = exports
    (DATA / "catalog.json").write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n")
    manifest["catalog_sha256"] = hashlib.sha256((DATA / "catalog.json").read_bytes()).hexdigest()
    (DATA / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    # Include a browsable reference even for modules with no prose manual.
    for module, info in catalog["modules"].items():
        lines = [f"# {module} — YARA-X {VERSION}", "", f"Source: {info['source']}", "",
                 "Generated from the official protobuf definitions and Rust exports. Availability depends on the engine build and field feature restrictions.", ""]
        visited = set()
        def describe(typ):
            if typ in visited or typ not in catalog["types"]:
                return
            visited.add(typ)
            lines.extend([f"## {typ}", ""])
            node = catalog["types"][typ]
            for name, field in node["fields"].items():
                collection = "array of " if field.get("repeated") else ""
                lines.extend([f"### {name}", "", f"Type: {collection}{field['type']}", "", field.get("documentation") or "No additional prose description in the upstream definition.", ""])
                if field.get("options"):
                    lines.extend(["Field annotations:", "```json", json.dumps(field["options"], indent=2), "```", ""])
                if field.get("unavailable_reason"):
                    lines.extend([field["unavailable_reason"], ""])
                lines.extend([f"Source: {field.get('source', info['source'])}", ""])
            for field in node["fields"].values():
                describe(field["type"])
        describe(info["root"])
        for name, overloads in catalog["functions"].items():
            for overload in overloads:
                if overload["module"] != module:
                    continue
                parameters = ", ".join(p["name"] + ": " + p["type"] for p in overload["parameters"])
                lines.extend([f"## {name}({parameters})", "", "Return type: " + overload["return_type"], "",
                              overload["documentation"] or "See the linked upstream implementation.", "", "Source: " + overload["source"], ""])
        target = DATA / "reference/generated_modules" / (module + ".md")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(lines))
    print(f"{len(catalog['modules'])} modules; {len(catalog['types'])} types; {exports} function overloads; {len(manifest['files'])} reference files")


if __name__ == "__main__":
    main(sys.argv[1])
