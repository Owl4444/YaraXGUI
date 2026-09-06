# Recovery and troubleshooting

## Search is taking too long

Click **Cancel**. The UI does not wait for the worker. If a worker does not stop
cooperatively, it is terminated separately. Completed partial results remain
available. Try a more specific pattern or a larger minimum string length.

A limit message means results were stopped intentionally. It does not mean the
whole file contains only that many matches. A timeout stops the worker; the file
and your edits remain untouched. Regex search uses Python byte-regex syntax.

## Recover unsaved work

Use **File → Recover Unsaved Work…**. Select a YARA draft or hex journal, then
**Restore selected**. Hex reconstruction happens in the background and writes a
separate recovered file. Damaged recovery data produces an error and is retained.
Recovery from another running instance is hidden until that instance exits.

On Windows the default location is `%LOCALAPPDATA%\YaraXGUI\recovery`.
On Linux it is `$XDG_DATA_HOME/YaraXGUI/recovery`, falling back to
`~/.local/share/YaraXGUI/recovery`. On macOS it is
`~/Library/Application Support/YaraXGUI/recovery`.

Do not delete this directory if you still need an unsaved draft. Recovery files
contain your data. Saving or explicitly discarding a document removes its recovery
entry. Copies restored to the `restored` subfolder are retained on disk.

## Recovery unavailable

Check available disk space and permissions. The first hex edit starts a baseline
snapshot; protection is incomplete until **Recovery up to date** appears. A slow
or full disk may delay or prevent protection. Save your working copy manually.
An original file changed externally during snapshot creation cannot be trusted
as the baseline; recovery reports that error instead of replaying edits onto it.

## Windows executable build cannot find Python

The build script detects an active or project virtual environment, Qt Creator's
Python environment, then `py -3` or `python`. It requires 64-bit Python 3.12+.
An explicit path can be supplied:

```bat
compile_to_exe.bat "C:\Path To Python\python.exe"
```

## Offline documentation

The YARA-X reference is bundled with the editor toolkit and matches its pinned
YARA-X version. Search covers document titles and contents. Embedded online links
open only when clicked. Compatibility notes explain unsupported wheel modules,
formatter restrictions and other differences.
