# YaraXGUI

YaraXGUI gives a graphical view of [Yara-x](https://github.com/virustotal/yara-x). As I foresee myself doing more YARA rule writings, I thought it might be a good time to learn more about ImGUI as well and YARA.


<img width="2559" height="1519" alt="image" src="https://github.com/user-attachments/assets/8cd98224-3c68-4cc8-9060-e75135703429" />

# Video Demo

Can watch from this [link](https://youtu.be/RYoayoBdKNQ)

## Usage

### YARA Rule Input
You can either:
- browse for YARA rule (.yara or .yar) files OR
- edit YARA rule right in the editor
- Yara-X with a more lax rules to support Yara - Read more about [this](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/)
- Since Yara-x binding it used, anything that yara-x can compile should also be compilable here.
- Supports [YARA modules](https://virustotal.github.io/yara-x/docs/modules/whats-a-module/)

### Scan Directory
- Select the browser that you want to scan recursively

### Compile YARA
- Compile the YARA rule which should indicate success or error

### Scan
- Once compilation is successful, we can now scan directory which should display more information

### Rule Metadata
These are information about the file which include:
- File name
- Size of the file
- Name space of the rule
- number of rules
  - This includes both Global and Private Rules
- number of patterns hit during the match
  - This does not include Global and Private rules

### Files with Matches Indications
This includes:
- File matched
- Rule that was used to get the hit (no global or private rule)
- Pattern Identifier
- File offset
- Data Preview
- Hexadecimal Preview

### Pattern Matches
This maps the file to the rule that was hit along with the actual data that were matched from the files.

### Exporting selected file results
- IR Report shows more information about all the matches that are displayed in the pattern matching table.
- Other two formats are `.csv` and `.json`

---

# Compiling YaraXGUI
For anyone that wants to compile this to adjust to your own liking, here's how!

## C++ 
Use at least C++17 and above.

## ImGUI
This project uses the latest version of [ImGUI](https://github.com/ocornut/imgui) at this point of writing. The example for DirectX Win32 was used as the base.

## ImGUI Text Editor
This project has plans to but have not yet implemented with either [ImGuiColorTextEdit](https://github.com/BalazsJako/ImGuiColorTextEdit] or [zep](https://github.com/Rezonality/zep) for the YARA Editor. 
Current editor is very limited since it is now using ImGUI's Multi input text instead for quick development. The `TextEditor.cpp` and `TextEditor.h` is not being used for now.

## Yara-X
Install rust to install `cargo-c` with `cargo`. Once we have `cargo`, run the following command:

```c
cargo install cargo-c
```

After which, we want to build the  C header for Yara-X. Run the following command within YARA-x root directory from [GitHub - VirusTotal/yara-x: A rewrite of YARA in Rust.](https://github.com/VirusTotal/yara-x):

```c
cargo cinstall -p yara-x-capi --release
```

We should find the relevant files of interests within `\target\x86_64-pc-windows-msvc\release`

```c
16/07/2025  07:09 pm    <DIR>          .
16/07/2025  07:02 pm    <DIR>          ..
16/07/2025  07:02 pm                 0 .cargo-lock
16/07/2025  07:02 pm    <DIR>          .fingerprint
16/07/2025  07:02 pm    <DIR>          build
16/07/2025  07:09 pm               195 cargo-c-yara-x-capi.cache
16/07/2025  07:08 pm    <DIR>          deps
16/07/2025  07:02 pm    <DIR>          examples
16/07/2025  07:09 pm    <DIR>          include
16/07/2025  07:02 pm    <DIR>          incremental
16/07/2025  07:09 pm            31,699 yara_x.h
16/07/2025  07:08 pm               452 yara_x_capi-uninstalled.pc
16/07/2025  07:08 pm            16,383 yara_x_capi.d
16/07/2025  07:08 pm             1,067 yara_x_capi.def
16/07/2025  07:08 pm        20,637,696 yara_x_capi.dll
16/07/2025  07:08 pm             7,294 yara_x_capi.dll.exp
16/07/2025  07:08 pm             9,072 yara_x_capi.dll.lib
16/07/2025  07:08 pm       130,731,254 yara_x_capi.lib
16/07/2025  07:08 pm               344 yara_x_capi.pc
16/07/2025  07:08 pm         8,990,720 yara_x_capi.pdb
              12 File(s)    160,426,176 bytes
               8 Dir(s)  362,276,708,352 bytes free

```

 This places the header and libraries in:
- **Header:** `target\x86_64-pc-windows-msvc\release\include\yara_x.h`
- **Import library:** `target\x86_64-pc-windows-msvc\release\yara_x_capi.dll.lib`
- **Static library:** `target\x86_64-pc-windows-msvc\release\yara_x_capi.lib`
- **DLL:** `target\x86_64-pc-windows-msvc\release\yara_x_capi.dll`
- **Module definition:** `target\x86_64-pc-windows-msvc\release\yara_x_capi.def`

### Setting Environment Variable

Next, we shall set the Environment Variable `YARAX_RELEASE` to `/path/to/yara-x\target\x86_64-pc-windows-msvc\release` for usage by MSVC project.
This allows MSVC to find the yara-x.h header during compilation.

---
