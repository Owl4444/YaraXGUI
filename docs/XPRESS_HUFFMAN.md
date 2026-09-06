# XPRESS Huffman recipe

In the Hex Editor, open **Apply Transform Recipe**, then add
**Compression → XPRESS Huffman decompress**. Select the complete compressed
payload and enter **Expected size (bytes)**: the original uncompressed length,
in decimal or `0x` hexadecimal. Apply to the selection, marked regions, or
entire file. For multiple regions, each region uses the same expected size.
The usual transform flow lets you expand the working buffer or save growing
output to a new file; in-place changes remain undoable.

This operation decodes raw **COMPRESSION_FORMAT_XPRESS_HUFF (4)** streams,
the Huffman variant accepted by Windows `RtlDecompressBufferEx`. It implements
the decoder in Python and works on Windows and Linux without extra packages.
It does not call `ntdll` or require a Windows installation at runtime.

## Input and limits

- The original size is required. Get it from the calling code or container
  metadata. Raw XPRESS Huffman does not record it, and symbol 256 can mean a
  match as well as an end marker. Guessing from that symbol can lose data.
- Supply the raw stream starting with its 256-byte Huffman table. Container
  headers such as Prefetch/MAM, SMB, and Windows Compression API framing must
  be removed first. Plain XPRESS, LZNT1, and XPRESS9 are different formats.
- Output is limited to **64 MiB per operation**, with a **2-second decoding
  budget** checked periodically. These limits also apply to previews. Even
  valid data can exceed the time budget on slower machines. An error returns
  no partial decoded result. The current recipe runner is synchronous, so it
  can pause briefly until that budget check; this is not a background job.
- Expected size is trusted, as with the native buffer API. Matches cannot
  overrun that size. Decoding stops once it produces that many bytes, allowing
  optional end markers and padding. An incorrect smaller size ending at a
  token boundary can produce a prefix. There is no checksum or corruption
  authentication in the raw format.
- The preview samples at most **4 KiB of compressed input**. If the complete
  payload fits, **Show N bytes** only limits the displayed dump, including
  when earlier recipe steps decode or transform the payload. Otherwise, the
  preview explains its limitation; **Apply** still processes the full chosen
  scope. This avoids treating a sample as a corrupt file.

## Implementation and validation

The decoder handles canonical Huffman tables, interleaved match-length bytes,
overlapping copies, history across blocks, and matches crossing 64 KiB block
boundaries. It also handles the Windows 32-bit extended match-length encoding.
It rejects incomplete/oversubscribed tables, truncated reads, backward
references outside the output, and output growth beyond the configured size.

References:

- [Microsoft MS-XCA, section 2.2.4: decoding](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/26db8e62-bbd8-472c-a09e-623f6de10f0b)
- [Microsoft MS-XCA, section 3.2: test examples](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/f59ff967-3032-4331-b108-0d2b4c09ee27)
- [RtlDecompressBufferEx API](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbufferex)
- [Microsoft clarification of long matches and block boundaries](https://lists.samba.org/archive/cifs-protocol/2022-November/003841.html)
- [Microsoft clarification of expected size and EOF](https://lists.samba.org/archive/cifs-protocol/2022-November/003862.html)
- [Samba's Windows-generated test corpus](https://github.com/samba-team/samba/tree/master/testdata/compression)

Offline tests include both MS-XCA examples, extended lengths, multiple blocks,
symbol-256 matches, every truncation of the long-match example, malformed
tables/references, size/time limits, mutations, recipe registration, and preview
behavior. A Windows-only test compresses with `RtlCompressBuffer` and compares
with `RtlDecompressBufferEx` directly; it is skipped on other platforms.

For additional interoperability coverage, set `XPRESS_TEST_CORPUS` to a local
checkout of Samba's `testdata/compression` directory before running
`python -m pytest tests/test_xpress_huffman.py`. This checks both Windows
compression levels byte-for-byte against their original data, without
downloading anything during tests. The corpus is not bundled with YaraXGUI.
