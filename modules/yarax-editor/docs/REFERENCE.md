# Offline reference map

The complete documentation tree is under
[`data/reference`](../src/yarax_editor/data/reference). The files are the official
versioned Markdown, including front matter and examples. The editor's offline
search reads these files directly.

| Topic | Bundled source |
|---|---|
| Rule anatomy, metadata, tags, comments | [syntax.md](../src/yarax_editor/data/reference/writing_rules/syntax.md) |
| Operators, literals, loops, `with`, references | [conditions.md](../src/yarax_editor/data/reference/writing_rules/conditions.md) |
| String modifiers and escapes | [text_patterns.md](../src/yarax_editor/data/reference/writing_rules/text_patterns.md) |
| Hex patterns | [hex_patterns.md](../src/yarax_editor/data/reference/writing_rules/hex_patterns.md) |
| Regex syntax | [regexps.md](../src/yarax_editor/data/reference/writing_rules/regexps.md) |
| Includes, globals, undefined values, private/global rules | [writing_rules](../src/yarax_editor/data/reference/writing_rules) |
| Module prose documentation | [modules](../src/yarax_editor/data/reference/modules) |
| Every module's schema fields and Rust exports | [generated_modules](../src/yarax_editor/data/reference/generated_modules) |
| Public language/library APIs and CLI | [api](../src/yarax_editor/data/reference/api), [cli](../src/yarax_editor/data/reference/cli) |
| Exact tokenizer and parser implementation | [grammar](../src/yarax_editor/data/grammar) |
| Protobuf fields, aliases, enum definitions, deprecations | [protos](../src/yarax_editor/data/protos) |
| Source provenance and checksums | [manifest.json](../src/yarax_editor/data/manifest.json) |

Online entry points: [official language documentation](https://virustotal.github.io/yara-x/docs/writing_rules/anatomy-of-a-rule/),
[official module documentation](https://virustotal.github.io/yara-x/docs/modules/whats-a-module/),
[versioned source](https://github.com/VirusTotal/yara-x/tree/v1.20.0).
