# YARA-X Editor Toolkit

A standalone Python language-service package and local browser playground. YaraXGUI
now uses this package through separate Qt and headless adapters. No Qt, yaraast, language-server process, CDN, or remote
lint service is required.

The compatibility target is **YARA-X 1.20.0**, official source commit
`60ad06971467029e77967e59d580cbbe85a1474d`. The dependency is deliberately pinned;
an engine/catalog version mismatch fails visibly instead of claiming compatibility.

## Run the editor

From this directory, in a Python 3.13+ virtual environment:

```sh
python -m pip install -e '.[test]'
yarax-editor demo --host 0.0.0.0 --port 8765
```

The default listens on all IPv4 interfaces. Open **http://127.0.0.1:8765** on
the server, or **http://<server-IP>:8765** from another machine. `0.0.0.0` is
the bind address; use the server's actual IP in your browser. To restrict access
to this machine, run `yarax-editor demo --host 127.0.0.1`.

The playground provides syntax colours, live
diagnostics, context-sensitive suggestions, signature help, documentation,
numbered snippets, formatting, offline reference search, and rule download.
It is a demonstration adapter for the standalone service, not a YaraXGUI integration.
The browser sends source to this server over HTTP for editor operations; no
third-party services are contacted. The demo has no authentication or TLS, so
use it on a trusted network. Host checks permit the destination interface IP,
localhost for loopback connections, or an explicitly configured bind hostname;
cross-origin requests are rejected. Arbitrary reverse-proxy hostnames are not
automatically trusted.
The demo does not read include files or configure external globals. Those options
are available through the Python API and CLI.

### Large files and formatting

Formatting is manual. The browser disables its Format button while a request is
pending; repeated keyboard shortcuts do not enqueue work. The server allows one
formatting job at a time across all clients, with at least one second between
starts. Work runs in a disposable process with a five-second timeout; timed-out
workers are terminated. The browser also recovers after an eight-second network
timeout. Failed or stale responses never replace the document.

Above **64 KiB of UTF-8 source**, live checks and automatic suggestions pause and
the editor uses plain text rendering. Check rule, Format and Ctrl Space remain
manual actions. Above **256 KiB**, interactive source operations are refused
before compilation; editing and download remain available. These bounds avoid
silently submitting huge pasted files. They are demo limits, not YARA-X language
restrictions. Native textarea editing is not virtualized for arbitrarily large files.

The CLI and synchronous `format_source` API remain available for batch formatting
without these interactive limits. UI adapters can share a `FormatRunner` and call
its blocking `format` method from a background thread. `timeout`, `interval`, and
`max_bytes` are configurable constructor arguments; preserve document revision
checks before applying its result. Programs using this process-based runner must
guard their entry point with `if __name__ == "__main__":`.

## Python API

```python
from yarax_editor import Compiler, CompileOptions, LanguageService, format_source

compiler = Compiler(CompileOptions(globals={"threshold": 1024}))
service = LanguageService(compiler)
source = 'import "pe" rule r { condition: pe.sections[0].raw'

suggestions = service.complete(source, len(source))
for item in suggestions:
    print(item.label, item.detail, item.edit)

valid_source = 'rule r { condition: with n = filesize : (n > threshold) }'
result = compiler.validate(valid_source)
assert result.valid
formatted = format_source(valid_source, compiler=compiler)
```

All public spans use **Python Unicode character offsets**, with exclusive ends.
`SourceMap` converts UTF-8 compiler byte ranges and LSP/Qt UTF-16 positions without
splitting surrogate pairs. `TextEdit` describes a replacement; `apply_edits`
checks bounds and overlap before changing anything.

`Document` provides undo/redo, snippet mirrors, and revision-gated results:

```python
from yarax_editor import Document

doc = Document('rule r { condition: fil')
doc.move_cursor(len(doc.text))
snapshot = doc.snapshot()
items = service.complete(snapshot.text, snapshot.cursor)
# This can run on a worker. Apply the result on the document owner's thread.
if doc.publish_completions(snapshot, items):
    doc.accept(snapshot, items[0])
```

An edit, undo, cursor movement, dismissal, or close invalidates pending completion
results. Diagnostics are tied to document revisions and disappear when text
changes. The document object itself belongs to one UI/controller thread; workers
receive immutable snapshots and return values. Compiler instances are created
and destroyed inside each validation call.

Other services:

- `signature_help(text, offset)`: overloads, parameter names/types, active argument.
- `hover(text, offset)`: function/field descriptions and source links.
- `highlights(text)`, `fold_ranges(text)`: portable rendering spans.
- `DocumentIndex(text).definitions(offset)` and `.references(offset)`: local navigation.
- `editing.newline_edit`, `toggle_line_comments`, `expand_snippet`: pure editing helpers.
- `Catalog.search_docs(query)`: full bundled offline Markdown references.

## What “compliance” means here

The official compiler is authoritative for syntax, type checking, scope,
modules, regex validity, and diagnostics. This supports all syntax accepted by
the pinned public Python engine, including nested `with`, loops, pattern sets,
modifiers, hex patterns, numeric literals, globals and explicitly enabled includes.
The tolerant editor index does not replace the compiler with a partial validator.

Formatting is **our own implementation**. It changes whitespace between tokens,
preserves literal/comment contents, verifies token identity, recompiles the result,
and checks that warnings have not changed. It does not call `yara_x.Formatter`.
Invalid source is left untouched. Literal internals, including multiline metadata
and hex contents, retain their original formatting. See [compatibility](docs/COMPATIBILITY.md)
for precise boundaries and the upgrade checklist.

The source catalog includes 21 module definitions, their nested fields and constant
namespaces, 131 exported overloads, 16 numeric-reading builtins and all 40 keywords.
Runtime suggestions are filtered to modules compiled into the installed engine.
Hosted-only fields and two parser-inaccessible reserved-name fields remain documented
but are not offered as usable suggestions.

## Offline specification and provenance

The package carries the complete versioned upstream documentation tree, module
protobuf definitions, tokenizer/parser implementation references, builtin definitions,
and parser/compiler/formatter fixtures. Generated per-module manuals cover fields
and functions even when upstream has no dedicated prose manual.

- [Reference index](docs/REFERENCE.md)
- [Bundled official manuals](src/yarax_editor/data/reference)
- [Generated module manuals](src/yarax_editor/data/reference/generated_modules)
- [Machine-readable symbol catalog](src/yarax_editor/data/catalog.json)
- [Source URLs and SHA-256 manifest](src/yarax_editor/data/manifest.json)
- [Upstream license and attribution](THIRD_PARTY_NOTICES.md)

These sources derive from the official [YARA-X documentation](https://virustotal.github.io/yara-x/docs/)
and [versioned implementation](https://github.com/VirusTotal/yara-x/tree/v1.20.0).

## CLI

```sh
yarax-editor check example.yar
yarax-editor format example.yar > formatted.yar
yarax-editor complete example.yar --offset 42
yarax-editor check example.yar --include-dir ./rules --globals '{"threshold":1024}'
yarax-editor docs 'with'
yarax-editor info
```

Formatting writes to stdout and never overwrites the input file.

## Tests and reference regeneration

```sh
python -m pytest
python -m pip install -e '.[browser]'
python -m playwright install chromium
python -m pytest browser_tests
```

The suite checks upstream fixtures against the actual compiler, every generated
field/constant path and exported function signature available in this build,
formatting idempotence, token/literal preservation, matching before and after
formatting, property-generated syntax, Unicode, scoped suggestions, diagnostic
lifetime, snippets, and browser interactions. Browser tests start their own local
server and stop it afterward. See [validation report](docs/VALIDATION.md).

Regenerate references only from a clean checkout of the pinned commit:

```sh
python -m pip install -e '.[reference]'
python tools/sync_reference.py /path/to/yara-x
```

The generator uses protobuf descriptors and their source annotations, walks enum
namespaces, and extracts every Rust `module_export` declaration including aliases
and overloads. It refuses unrecognized exports and a mismatched or modified source
checkout. Runtime use needs neither protobuf nor the source checkout.
