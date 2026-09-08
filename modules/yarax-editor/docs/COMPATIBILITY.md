# Compatibility contract

## Version and engine boundary

YaraXGUI and the editor toolkit require **Python 3.13 or newer**.

The tested target of this package revision is the **public Python wheel
`yara-x==1.20.0`**, corresponding to upstream commit
`60ad06971467029e77967e59d580cbbe85a1474d`. “Compatible” means accepting/rejecting
source with this compiler and keeping editor operations faithful to that source.
It is not a promise about future releases or every hosted/custom engine build.

The engine supplies the complete language parser and semantic validator. The
editor supplies lossless tokenization, a tolerant declaration index, suggestions,
navigation, formatting, revision management, and rendering/edit spans.

| Area | Handling |
|---|---|
| Declarations | Imports, includes, global/private rules, tags, metadata, pattern and condition sections |
| Literal text | Escapes, URLs/comment markers, multiline metadata; preserved exactly |
| Patterns | Text, regex flags/escapes, hex bytes/nibbles/negation/jumps/alternatives; validity delegated to YARA-X |
| Conditions | Complete compiler grammar, arithmetic/bitwise/logical operators, quantifiers, anonymous patterns, offsets/counts/lengths, rule references |
| Modern syntax | `with`, nested bindings/loops, `.len()`, octal/underscored literals, floating-point readers |
| Libraries | All versioned schema definitions and Rust exports; runtime module availability from `module_names()` |
| Includes/globals | Explicit `CompileOptions`; include-file diagnostic origins retained |
| Incomplete edits | Lossless classification and best-effort suggestions; never reported valid by a substitute grammar |
| Formatting | Whitespace-only, token identity, compiler validity and warning-set checks; literal interiors retained |
| Coordinates | Python offsets internally; strict UTF-8/UTF-16 conversion at boundaries |

## Known and deliberate boundaries

- The 1.20.0 wheel used here exposes 17 modules, including upstream test modules.
  The source catalog also documents optional modules missing from that wheel.
  A custom module needs a regenerated/extended catalog to receive rich suggestions;
  the compiler still governs its validity.
- VirusTotal hosted fields with `accept_if` feature restrictions cannot be enabled
  through this wheel's public compiler API. Their definitions remain in the offline
  reference; suggestions suppress them under the default runtime configuration.
- The upstream schemas contain `dex.strings` and `macho.segments[].filesize`.
  Those field names are reserved tokens rejected by this release's parser. The
  catalog labels them unavailable and tests verify the rejection. We do not invent
  an escape syntax or an alternate field name.
- Integer reading builtins stop at 32 bits; `uint64`/`int64` suggestions would be
  incorrect for this engine. Floating readers include 32- and 64-bit variants.
- Scope/type inference for suggestions covers declarations, pattern references,
  sequential `with` bindings, common loop variables, module paths, indexed arrays,
  maps and configured external structures. It is an editor aid, not a complete
  semantic AST/type inference API. Arbitrary computed expressions can validate
  correctly while offering less-specific suggestions.
- Snippets support numbered stops, defaults, mirrors, choices and escapes.
  Arbitrary LSP transformations/environment variables are not evaluated.
- The toolkit exposes navigation/folding spans; the browser demo does not implement
  every possible desktop editor interaction. Includes/globals and document undo/redo
  are available through the Python API. YaraXGUI provides its own Qt adapter and
  uses native Qt undo/redo with revision-gated toolkit results.
- The browser demo binds all IPv4 interfaces by default (`--host 127.0.0.1`
  restricts it to loopback). It has no authentication or TLS and sends source
  from the browser to the server over HTTP. Use a trusted network and the server's
  IP address; arbitrary proxy hostnames and IPv6 listeners are not supported.
  Request bodies are limited to 2 MB and interactive source to 256 KiB in UTF-8.
  Above 64 KiB, checks/completion become manual and highlighting is disabled.
  Formatting is limited to one active worker, one start per second and five
  seconds of worker execution; the worker is terminated on timeout. This is a
  demonstration server, not a hardened multi-user deployment or virtualized
  large-file editor. The synchronous batch formatter has no interactive limits.
- The public text API accepts Unicode strings. Invalid UTF-8 files are rejected by
  the CLI instead of silently replacing bytes. A future binary-source adapter needs
  a separate byte-preserving contract.
- Formatter refusal is safe: invalid input, changed token identity, changed warnings,
  or output rejected by YARA-X returns an error and never modifies the source.

## Upgrading

1. Select an upstream release and record its exact commit.
2. Update the dependency, engine guard, and generator pins together.
3. Regenerate the documentation, schemas, exports, builtins and fixture snapshots.
4. Investigate added/removed tokens, overloads, aliases, enum layouts and restrictions.
5. Run corpus, catalog, generated, editing, browser and wheel-isolation tests.
6. Update the coverage report and known discrepancies before claiming the new target.

No GitHub issue turnaround is needed for changes to the owned editor code. Compiler
language semantics remain a YARA-X dependency; a compiler bug requires an engine
update or an independently maintained engine fork.
