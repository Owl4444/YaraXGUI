# YaraXGUI user guide

## Rules and scanning

Use **File → Open YARA File…** to open a rule in an editor tab.
**Open YARA Folder…** loads a collection into the Rule Browser.
Choose a target using **File → Select Scan Folder…**. The directory panel
controls which files are selected or excluded. **Scan** uses the active rule tab.

Save your rule with **Save Rule** or **Ctrl+S**. The current save flow asks for
a destination. Formatting uses **Format YARA** or **Ctrl+Shift+F**.
**Save Rule**, **Format YARA**, and **Scan** stay together above the editor.
Use **File → Reset…** to clear the workspace after confirmation.

**View → Reset Layout** restores a single panel group on the right, with
**Scan Directory** active and **Rule Repository** and **MWDB** as tabs beneath
it. Scan Results, Rule Browser, and other plugin panels are hidden; reopen them
from **View** when needed. Resetting the layout preserves your rules and scan
data. New installations use this layout; existing saved arrangements still
restore until you reset or rearrange them.

## Offline help

The search field at the top of Help filters documents by title and contents.
To find text within the current page, press **Ctrl+F**. **Enter** or **F3** moves
to the next match; **Shift+Enter** or **Shift+F3** moves backwards. Search ignores
case, wraps at the page boundary, and reports when there are no matches.
**Esc** closes the find bar while keeping Help open.

Use **Settings → Editor Settings…** to choose the shared UI font and size.
Editor fonts have a separate setting. Help uses larger reading text and headings.

## Editing repository rules

In the Rule Repository, choose **Edit Rule** or double-click an entry. It opens
in the full YARA editor with highlighting, diagnostics, completion, and formatting.
Use **Update Repository** above the editor, or **Ctrl+S**, to update that same
entry. Before anything is written, a review dialog shows removed lines in red
and added lines in green. You can switch between **Changes**, **Saved version**,
and **Proposed version**, and enable **Show whitespace**. Choose **Confirm
Update** to save; **Cancel**, Escape, or closing the review leaves your draft
intact. Cancel is the default action. This also applies when saving during tab
or window closing. Unchanged text does not need confirmation.

Large reviews are paged without omitting content. Very large changes use a
complete replacement of the changed region to keep comparison responsive.
If the draft or repository changes during review, the update is stopped so
unreviewed content cannot be written.

The context row shows the rule name, repository, and saved/unsaved state.
Reopening an entry focuses its existing draft without replacing your edits.

**Metadata…** edits the repository's name, tags, family, and other descriptive
fields. **Add as New…** creates a separate entry from the active editor and
opens it for future updates. **Save Copy As…** exports a linked tab to a file
without changing its repository destination. **Reload from Repository** fetches
the saved version and asks before discarding pending edits. Closing a modified
repository tab offers to update its original entry.

Changing the selected row does not change an open tab's destination. If you
switch the local/remote connection, switch back before updating that tab.
Deleted entries and conflicting source changes leave your draft intact. The
current API also checks the original source atomically when saving; update
older remote servers to get this protection against simultaneous writes.

## Server credentials

Set the YaraXGUI server URL and API key in **Settings → Editor Settings… →
Connections & Credentials**. The remote Rule Repository and the MWDB tab's
YaraXGUI API requests use that saved key automatically. The repository tab has
no separate key field. Changing or clearing the key takes effect on subsequent
requests without restarting. Existing keys saved in settings remain supported;
the OS keyring is preferred when available.

## Editing large rules

Above 64 KiB UTF-8, automatic highlighting, checks, suggestions, smart indentation
and bracket pairing pause. They resume when the document shrinks. A persistent
indicator identifies this mode. Manual formatting/checks/completion accept up to
256 KiB. Large files remain editable and saveable.

## Binary search and strings

Open a file in the Hex Editor. **Ctrl+F** opens Hex, Text and Regex search.
Find Next, Find Previous and Find All run in isolated worker processes.
The **Strings** panel extracts printable ASCII and ASCII-range UTF-16LE strings,
including CR/LF and both byte alignments. This is not full Unicode word detection.

**Cancel** remains available while preparing a snapshot or searching. Results
already received are retained on cancellation. Changing a file or editing its
bytes invalidates analysis results. Search errors affect the worker, not the editor.

Results arrive incrementally. One job returns at most 50,000 rows and a 16 MiB
estimated result budget. String previews contain up to 256 characters. Double-click
a result to inspect its entire range in the hex view. Right-click **View string…**
to load text on demand (up to 1 MiB). Filtering searches the displayed previews,
offsets, lengths and encodings; use Text/Regex search to find content beyond previews.

Two analysis jobs may run concurrently. Searches have a 120-second worker time limit
and a 512 MiB allocation allowance (plus virtual space for the input mapping on
Unix). Windows applies a process private-memory limit. A worker that cannot apply
its memory limit reports an error instead of starting an unbounded search.
Preparation copies the current bytes to a temporary snapshot and needs free disk
space roughly equal to the file size. Cancellation cleans up its temporary files.

## Hex editor menus

With the hex/text view focused, use **Ctrl+mouse wheel** or **Ctrl++ / Ctrl+−**
to resize its font. **Ctrl+=** also zooms in; **Ctrl+0** restores the configured
size. The same controls appear in **View**. Zoom preserves your selection and
keeps the area you are viewing in place. Plain scrolling still scrolls the file.
Long lines in Text View can scroll horizontally; only the visible portion is
rendered, including when zoomed out.

The top menus group actions by task:

- **File:** open, save/export, revert, close.
- **Edit:** undo/redo, copy/paste, insert/fill, read-only mode.
- **Navigate:** find, go to offset, previous/next result file.
- **Analyze:** transforms, binary comparison, entropy graph, disassembly/CFG.
- **View:** text/hex display, text options, line numbers, layout, and panels.

The main toolbar keeps Open, Find, Go to, Transform, Display, and Read-Only.
**Display → Layout** contains Bytes per row; **Display → Panels** controls docks.
Previous/next file controls appear only when browsing multiple result files.
Existing keyboard shortcuts continue to work.

## Entropy and transform previews

The Entropy panel's **File entropy** measures all current bytes, equivalent to
`math.entropy(0, filesize)` when YARA-X scans those same bytes. Section labels use
the exact section byte ranges, with ranges clipped at EOF. Hover over a section
for its value and matching `math.entropy(offset, length)` expression.
The graph still shows individual block entropies; changing **Block size** changes
the graph's detail, not the file or section entropy. Unsaved edits are included.

Use **+ / −** or the mouse wheel to zoom the entropy graph. Wheel zoom stays
centered on the pointer. Drag to pan, or use the horizontal scrollbar; **Fit
File** restores the full view. A click still navigates the hex editor to that
byte, while a drag only pans. The range indicator and axis labels show the
visible bytes. Zooming does not recalculate entropy; increase detail by choosing
a smaller block size and calculating again. At overview scale, blocks sharing
a pixel retain their highest entropy so narrow peaks remain visible.

The transform dialog keeps recipe steps beside the **Input** and **Output**
previews. Drag the dividers to adjust their space, use **Expand preview** to hide
the recipe temporarily, and **A− / A+** to change both preview fonts. You can
maximize the dialog. **Show debug log** opens the log; output or errors open it
automatically. Adding steps scrolls the recipe without shrinking the previews.

Click the **Add operation** dropdown and start typing to search any part of an
operation's name, without matching case. Select a result with the mouse or the
arrow keys and **Enter**, then click **Add to Recipe**. An incomplete or unknown
name disables Add, so it cannot insert the previous selection by mistake.
**Escape** cancels an unfinished search without closing the recipe dialog.

Recipes chain operations for encoding, byte manipulation, decryption,
compression, hashing, text processing, and Python scripting. Each enabled step
uses the previous step's output. Reorder or bypass steps to compare results,
then choose the current selection, marked regions, or entire file as the scope.
Use **Inspect step** to check intermediate output and each operation's help for
its required parameters. See [Transform recipes](RECIPES.md) for the workflow,
examples, preview limits, and saving results.

## Saving and recovery

Hex edits change a working copy. **Save As…** writes the whole edited binary.
Closing a modified hex window or switching files prompts to save, discard or cancel.
An empty edited file can also be saved.

YARA recovery drafts are captured about one second after editing starts. For
larger rules the interval increases to 3, 5 or 10 seconds to reduce copying and
disk traffic while typing. Hex recovery makes one baseline copy, then
journals byte replacements (including insert/delete, undo/redo and transforms).
Disk writes happen in the background. Check the hex status bar: **Recovery up to
date** means the queued edits have reached the journal.

After an abnormal exit, recovery offers separate copies. You can also use
**File → Recover Unsaved Work…**. Recovery never overwrites original files.
**Keep for later** retains drafts. Save or explicitly discard a recovered document
to remove its old recovery entry.

Recovery is a safety net, not a replacement for saving. A crash before the initial
hex snapshot finishes, or before pending writes reach disk, can lose recent edits.
Disk errors or a 64 MiB pending hex-patch backlog are reported; save manually if
recovery becomes unavailable. Recovery files are stored in the user's YaraXGUI data
folder and may contain sensitive source or binary data.


## Disassembly and CFG

- The listing uses file offsets for hex navigation. Selections wholly inside a file-backed PE section or ELF load segment are decoded at their virtual address, with direct branch destinations mapped back to file offsets. Raw selections use their file offset as the decoder base.
- The CFG uses layered blocks with joins below their forward predecessors, separate disconnected regions, and exterior routes for loops. **T**, **F**, and **J** mark taken branches, fallthrough, and unconditional jumps.
- **Fit graph**, **100%**, and **Reset layout** control the view. **Compact blocks** hides the middle of long blocks while keeping their ending visible; turn it off to expand them. Hover for the full listing. Enable **Edge handles** to adjust routes manually.
- CFG analysis covers x86, ARM/Thumb, and ARM64. MIPS/PPC remain available in the listing; CFG and call analysis are explicitly unavailable for those architectures. ELF auto-detection respects endianness.
- This is a linear-sweep view of the selected bytes, with inferred function boundaries, rather than complete function recovery. Unknown indirect branches, external destinations, and undecoded data are marked. Capstone itself documents the [limitations of decoding through unknown data](https://www.capstone-engine.org/skipdata.html).
- Graphs above 1,500 nodes request a smaller selection; the virtual listing remains available for large inputs.

## MWDB

Configure your MWDB HTTPS URL and credentials in Settings, then connect from
the MWDB tab. Its YaraXGUI API requests use the shared server URL and API key.
Browse/search files, select a rule and run a retrohunt. Server-to-server scans
return results and match previews; using a Download action explicitly saves
sample files to your computer. The API server permits only its configured
MWDB destination. See [server settings](API_SECURITY.md#limits-and-settings).

## Repository storage and backups

Use Local mode for a per-user database without a server. The panel shows its
location. Remote mode stores repository saves on the connected server. Editing
a draft does not save it until you update the repository entry.
See the [cheatsheet](CHEATSHEET.md#where-your-rules-live) for storage locations
and [backup/migration instructions](REPOSITORY_BACKUPS.md) for portable copies.
