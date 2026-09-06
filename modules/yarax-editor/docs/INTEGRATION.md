# YaraXGUI integration

YaraXGUI's desktop and headless API now use this independently packaged module.
The old `yr-ls` client/executable, hard-coded completion catalog and duplicate
lexer were removed. The scanning engine remains pinned to YARA-X 1.20.0.

## Adapters

- `editor_backend.py` owns Qt background scheduling and Unicode conversions.
  Analysis/completion requests coalesce to the latest pending request per tab.
  Replies are checked against document identity, edits and cursor state. Compiled
  PyO3 objects never cross from worker threads into Qt.
- `yara_editor.py` owns widget interactions. It uses toolkit completion edits,
  snippet expansion/mirroring, indentation, hover and signature information.
  Formatting applies to its originating tab, retains newer edits and forms one
  native Qt undo step. Closed tabs drop pending replies.
- `yara_highlighter.py` renders toolkit spans, including comments inside hex
  patterns. Ordinary strings and regexes retain literal comment markers.
- `editor_services.py` provides the shared bounded formatter and compiler-backed
  rule information. The scanner retains its conservative file-size optimization,
  with lexical masking supplied by the toolkit.
- The REST formatting and validation routes run their work outside the API event
  loop. Formatting failures retain the existing `success: false` response contract.

The desktop and API preserve the engine's existing include support. Included-file
diagnostics keep their origin and are not rendered against a guessed location in
the current document. The independent browser demo keeps includes disabled.

## Interactive limits

The desktop follows the browser's 64 KiB UTF-8 threshold for automatic work and
256 KiB limit for manual interactive source operations. Ctrl+Shift+L validates
manually; Ctrl+Space requests suggestions; Ctrl+Shift+F requests formatting.
Formatting allows one active job across tabs, at least one second between starts,
and five seconds of worker execution. A closed document can finish an already
running bounded job, but its result is discarded. Batch CLI formatting remains
available without the interactive size limit.

## Installation and packaging

From the repository root, install `requirements.txt` for the desktop, or
`requirements-server.txt` for the API. Both install the local module and pin the
engine. For development on the module, use `pip install -e modules/yarax-editor`.

The PyInstaller spec collects the package, catalog, references and YARA-X version
metadata. Multiprocessing support diverts frozen worker startup before Qt imports.
The Dockerfile copies and installs the module and headless adapters.

## Verification

- **154 desktop/API tests passed**, with two existing dependency deprecation warnings.
- **2,510 standalone/Chromium tests passed**.
- A Linux PyInstaller build succeeded and launched with the offscreen Qt platform.
- Its bundled executable successfully ran the formatting worker under the default
  five-second limit (4.61 seconds including a cold executable extraction in the test).
- The staged headless API started, validated and formatted a `with` rule with
  literal comment markers in an environment without PySide6.
- Docker execution was unavailable because access to the daemon socket was denied.
  The corresponding copied server layout was exercised directly instead.
- Windows/macOS frozen builds were not exercised on this Linux host.
