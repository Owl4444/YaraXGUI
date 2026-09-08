# Transform recipes

Recipes apply a sequence of operations to bytes in the Hex Editor. Each enabled
step receives the previous step's output, so you can combine decoding,
decryption, decompression, and other transforms in one operation.

## Build a recipe

1. Open a file in the Hex Editor and choose **Apply Transform Recipe**.
2. Search **Add operation** by typing part of an operation's name. Select a
   result and click **Add to Recipe**.
3. Fill in that step's parameters. Its help explains the accepted key format,
   modes, sizes, and other requirements.
4. Add more steps as needed. Use the arrows to reorder them, the checkbox to
   bypass a step, or the remove button to delete it.
5. Inspect the preview, choose a scope, and click **Apply**.

Step order matters. For example, a Base64-encoded compressed payload needs
**Base64 decode** before the matching decompression operation. Start with the
bytes you actually have, then add one step at a time and inspect the result.

## Operation groups

| Group | Examples and uses |
|---|---|
| Encoding | Base64 and hex encoding or decoding |
| Bitwise | XOR, NOT, byte reversal, letter rotation, and XOR key searches |
| Symmetric crypto | AES, RC4, and ChaCha20 with the required keys and mode parameters |
| Compression | Compress or decompress using the format that matches the input |
| Hashing | Hashes, HMAC, checksums, and digest reports |
| Text | Literal or regex replacement, regex extraction, case conversion, and NULL removal |
| Python | Expressions, scripts, or a script file for custom byte processing |

The operation picker is the full catalog. Read the selected operation's help
for format-specific requirements: keys and IVs have defined sizes, some modes
need authentication tags, and some compressed formats need the original output
size or a complete payload. Select the payload boundaries appropriate to that
format. Hashing and report operations produce new output bytes too.

## Preview and troubleshoot

**Input** and **Output** show the bytes around each transformation. Use
**Inspect step** to compare intermediate results; the final step shows the
recipe's resulting output. **Show** controls the number of displayed bytes.
The preview works with a sample of up to 4 KiB; **Apply** processes the full
chosen scope. Operations that require complete input may be unavailable in the
preview when the sample is too small.

Open **Show debug log** for operation messages and errors. If a step fails,
inspect its input, check its parameters, and bypass later steps while adjusting
it. Preview success on a sample does not guarantee that the full input will
process successfully. Size and time limits depend on the operation.

Drag the dividers, maximize the dialog, or use **Expand preview** to give the
byte dumps more space. **A− / A+** change both preview fonts.

## Scope and output

Choose **Current selection**, **Marked regions**, or **Entire file**. With
marked regions, the same recipe and parameters apply to each region separately.
Check the selected scope before applying; existing marked regions take priority
when the dialog chooses its initial scope.

Transforms can change the output length. Follow the output-size prompt when
offered to expand the working buffer or save the transformed output to a new
file. Changes made in the Hex Editor remain undoable. Use **Save As…** to write
the edited binary to disk; see [Saving and recovery](USER_GUIDE.md#saving-and-recovery).
