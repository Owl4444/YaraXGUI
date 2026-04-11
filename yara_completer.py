# -*- coding: utf-8 -*-
"""YARA autocompletion engine and popup for YaraTextEdit."""

import re
from dataclasses import dataclass
from typing import List, Optional

from PySide6.QtCore import Qt, Signal, QTimer, QPoint
from PySide6.QtGui import QColor, QFont, QKeyEvent, QTextCursor
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QListWidget,
                               QListWidgetItem, QLabel, QTextEdit,
                               QApplication)


# ── Completion item data ─────────────────────────────────────────

@dataclass
class CompletionItem:
    label: str          # display text
    insert_text: str    # text to insert
    kind: str           # "keyword", "module", "function", "attribute", "variable", "snippet", "meta_key"
    detail: str = ""    # type info / description
    snippet: bool = False  # True if insert_text contains $0 placeholder

    @property
    def icon(self) -> str:
        icons = {
            "keyword": "\u25b6",   # ▶
            "module": "\u25a0",    # ■
            "function": "\u0192",  # ƒ
            "attribute": "\u25cf", # ●
            "variable": "$",
            "snippet": "\u25b6",   # ▶
            "meta_key": "\u25cf",  # ●
        }
        return icons.get(self.kind, "\u25b6")


# ── Keyword / builtin data ───────────────────────────────────────

_YARA_KEYWORDS = [
    CompletionItem("rule", 'rule rule_name {\n    meta:\n        author = ""\n        description = ""\n    strings:\n        $s1 = "$0"\n    condition:\n        any of them\n}', "snippet",
                   "Full rule template | rule suspicious_pdf { ... }",
                   snippet=True),
    CompletionItem("import", 'import "$0"', "keyword",
                   'Import a YARA module | import "pe"  import "math"',
                   snippet=True),
    CompletionItem("include", 'include "$0"', "keyword",
                   'Include another .yar file | include "common_rules.yar"',
                   snippet=True),
    CompletionItem("private", "private ", "keyword",
                   "Rule won't appear in scan output | private rule helper { ... }"),
    CompletionItem("global", "global ", "keyword",
                   "Rule must match for all other rules | global rule is_pe { ... }"),
    CompletionItem("true", "true", "keyword", "Boolean literal"),
    CompletionItem("false", "false", "keyword", "Boolean literal"),
    CompletionItem("with", "with $0 : ( )", "snippet",
                   "Scoped variable binding (YARA-X) | with x = 100 : ( x == 100 )",
                   snippet=True),
]

_CONDITION_KEYWORDS = [
    CompletionItem("and", "and ", "keyword",
                   "Logical AND | $s1 and $s2 and filesize < 1MB"),
    CompletionItem("or", "or ", "keyword",
                   "Logical OR | $s1 or $s2"),
    CompletionItem("not", "not ", "keyword",
                   "Logical NOT | not $s1"),
    CompletionItem("any of them", "any of them", "snippet",
                   "True if any defined string matches | condition: any of them"),
    CompletionItem("any of", "any of ($0)", "snippet",
                   "Any of named strings | any of ($s1, $s2)  any of ($s*)",
                   snippet=True),
    CompletionItem("all of them", "all of them", "snippet",
                   "True if every defined string matches | condition: all of them"),
    CompletionItem("all of", "all of ($0)", "snippet",
                   "All of named strings | all of ($api*)  all of ($s1, $s2)",
                   snippet=True),
    CompletionItem("none of them", "none of them", "snippet",
                   "True if zero strings match | condition: none of them"),
    CompletionItem("none of", "none of ($0)", "snippet",
                   "None of named strings | none of ($false_pos*)",
                   snippet=True),
    CompletionItem("any", "any ", "keyword",
                   "Quantifier: at least one | any of them"),
    CompletionItem("all", "all ", "keyword",
                   "Quantifier: every one | all of them"),
    CompletionItem("none", "none ", "keyword",
                   "Quantifier: zero matches | none of them"),
    CompletionItem("of", "of ", "keyword",
                   "Pairs with a quantifier | 2 of ($s*)  any of them"),
    CompletionItem("them", "them", "keyword",
                   "Refers to all string identifiers | any of them"),
    CompletionItem("for any of them", "for any of them : ($0)", "snippet",
                   "Iterate strings with a sub-condition | for any of them : ($ at 0)",
                   snippet=True),
    CompletionItem("for all of them", "for all of them : ($0)", "snippet",
                   "Every string must satisfy sub-condition | for all of them : (# > 2)",
                   snippet=True),
    CompletionItem("for", "for $0 of them : ( )", "snippet",
                   "Count-based loop | for 2 of them : ($ at pe.entry_point)",
                   snippet=True),
    CompletionItem("with", "with $0 : ( )", "snippet",
                   "Scoped variable binding (YARA-X) | with x = 100 : ( x == 100 )",
                   snippet=True),
    CompletionItem("in", "in ", "keyword",
                   "Byte range operator | $s1 in (0..1024)  $s1 in (pe.entry_point..filesize)"),
    CompletionItem("at", "at ", "keyword",
                   "Exact offset match | $mz at 0  $sig at pe.entry_point"),
    CompletionItem("matches", "matches ", "keyword",
                   "Regex match on string | pe.pdb_path matches /\\\\Release\\\\/"),
    CompletionItem("contains", "contains ", "keyword",
                   "Substring check | pe.dll_name contains \"kernel\""),
    CompletionItem("startswith", "startswith ", "keyword",
                   "String prefix check | pe.pdb_path startswith \"C:\\\\\""),
    CompletionItem("endswith", "endswith ", "keyword",
                   "String suffix check | pe.dll_name endswith \".dll\""),
    CompletionItem("icontains", "icontains ", "keyword",
                   "Case-insensitive contains | pe.dll_name icontains \"KERNEL\""),
    CompletionItem("istartswith", "istartswith ", "keyword",
                   "Case-insensitive startswith | pe.pdb_path istartswith \"c:\\\\\""),
    CompletionItem("iendswith", "iendswith ", "keyword",
                   "Case-insensitive endswith | pe.dll_name iendswith \".DLL\""),
    CompletionItem("iequals", "iequals ", "keyword",
                   "Case-insensitive equals | pe.dll_name iequals \"kernel32.dll\""),
    CompletionItem("defined", "defined ", "keyword",
                   "True if value exists (not undefined) | defined pe.dll_name"),
    CompletionItem("filesize", "filesize", "builtin",
                   "Size of the scanned file in bytes | filesize < 500KB  filesize > 1MB"),
    CompletionItem("entrypoint", "entrypoint", "builtin",
                   "Deprecated \u2014 use pe.entry_point | $mz at entrypoint"),
    CompletionItem("KB", "KB", "keyword",
                   "Multiply by 1024 | filesize < 500KB"),
    CompletionItem("MB", "MB", "keyword",
                   "Multiply by 1048576 | filesize < 10MB"),
    CompletionItem("uint8", "uint8($0)", "function",
                   "Read unsigned 8-bit int (LE) | uint8(0) == 0x4D",
                   snippet=True),
    CompletionItem("uint16", "uint16($0)", "function",
                   "Read unsigned 16-bit int (LE) | uint16(0) == 0x5A4D",
                   snippet=True),
    CompletionItem("uint32", "uint32($0)", "function",
                   "Read unsigned 32-bit int (LE) | uint32(0) == 0x00905A4D",
                   snippet=True),
    CompletionItem("uint64", "uint64($0)", "function",
                   "Read unsigned 64-bit int (LE) | uint64(offset)",
                   snippet=True),
    CompletionItem("int8", "int8($0)", "function",
                   "Read signed 8-bit int (LE) | int8(0) < 0",
                   snippet=True),
    CompletionItem("int16", "int16($0)", "function",
                   "Read signed 16-bit int (LE) | int16(pe.entry_point)",
                   snippet=True),
    CompletionItem("int32", "int32($0)", "function",
                   "Read signed 32-bit int (LE) | int32(0x3C)",
                   snippet=True),
    CompletionItem("int64", "int64($0)", "function",
                   "Read signed 64-bit int (LE) | int64(offset)",
                   snippet=True),
    CompletionItem("uint8be", "uint8be($0)", "function",
                   "Read unsigned 8-bit int (BE) | uint8be(0)",
                   snippet=True),
    CompletionItem("uint16be", "uint16be($0)", "function",
                   "Read unsigned 16-bit int (BE) | uint16be(0) == 0x4D5A",
                   snippet=True),
    CompletionItem("uint32be", "uint32be($0)", "function",
                   "Read unsigned 32-bit int (BE) | uint32be(0) == 0x7F454C46",
                   snippet=True),
    CompletionItem("uint64be", "uint64be($0)", "function",
                   "Read unsigned 64-bit int (BE) | uint64be(offset)",
                   snippet=True),
    CompletionItem("int8be", "int8be($0)", "function",
                   "Read signed 8-bit int (BE) | int8be(0)",
                   snippet=True),
    CompletionItem("int16be", "int16be($0)", "function",
                   "Read signed 16-bit int (BE) | int16be(offset)",
                   snippet=True),
    CompletionItem("int32be", "int32be($0)", "function",
                   "Read signed 32-bit int (BE) | int32be(0)",
                   snippet=True),
    CompletionItem("int64be", "int64be($0)", "function",
                   "Read signed 64-bit int (BE) | int64be(offset)",
                   snippet=True),
    CompletionItem("float32", "float32($0)", "function",
                   "Read 32-bit IEEE 754 float | float32(offset) > 1.0",
                   snippet=True),
    CompletionItem("float64", "float64($0)", "function",
                   "Read 64-bit IEEE 754 float | float64(offset) > 1.0",
                   snippet=True),
    CompletionItem("float32be", "float32be($0)", "function",
                   "Read 32-bit float (BE) | float32be(offset)",
                   snippet=True),
    CompletionItem("float64be", "float64be($0)", "function",
                   "Read 64-bit float (BE) | float64be(offset)",
                   snippet=True),
]

_STRING_MODIFIERS = [
    CompletionItem("ascii", "ascii", "keyword",
                   "Match ASCII encoding (default) | $s = \"cmd\" ascii wide"),
    CompletionItem("wide", "wide", "keyword",
                   "Match UTF-16LE encoding | $s = \"cmd\" wide  (finds c\\x00m\\x00d\\x00)"),
    CompletionItem("nocase", "nocase", "keyword",
                   "Case-insensitive matching | $s = \"malware\" nocase"),
    CompletionItem("fullword", "fullword", "keyword",
                   'Match only at word boundaries | $s = "evil" fullword  (won\'t match "medieval")'),
    CompletionItem("xor", "xor", "keyword",
                   "XOR each byte with keys 0x00-0xFF | $s = \"This program\" xor"),
    CompletionItem("xor(range)", "xor($0)", "snippet",
                   "XOR with a specific key range | $s = \"secret\" xor(0x01-0xFF)",
                   snippet=True),
    CompletionItem("base64", "base64", "keyword",
                   "Match Base64-encoded form | $s = \"admin\" base64"),
    CompletionItem("base64(alphabet)", 'base64("$0")', "snippet",
                   "Base64 with custom alphabet | base64(\"A-Za-z0-9+/\")",
                   snippet=True),
    CompletionItem("base64wide", "base64wide", "keyword",
                   "Match Base64-encoded UTF-16 form | $s = \"admin\" base64wide"),
    CompletionItem("base64wide(alphabet)", 'base64wide("$0")', "snippet",
                   "Base64wide with custom alphabet | base64wide(\"A-Za-z0-9+/\")",
                   snippet=True),
    CompletionItem("private", "private", "keyword",
                   "String won't show in match output | $helper = \"MZ\" private"),
]

_META_KEYS = [
    CompletionItem("author", 'author = "$0"', "meta_key",
                   'Rule author | author = "YARA Team"', snippet=True),
    CompletionItem("description", 'description = "$0"', "meta_key",
                   'What the rule detects | description = "Detects Cobalt Strike beacon"',
                   snippet=True),
    CompletionItem("date", 'date = "$0"', "meta_key",
                   'Creation/update date | date = "2025-03-15"', snippet=True),
    CompletionItem("reference", 'reference = "$0"', "meta_key",
                   'Link to report or source | reference = "https://example.com/report"',
                   snippet=True),
    CompletionItem("hash", 'hash = "$0"', "meta_key",
                   'Known sample hash | hash = "d41d8cd98f00b204e9800998ecf8427e"',
                   snippet=True),
    CompletionItem("tlp", 'tlp = "$0"', "meta_key",
                   'Traffic Light Protocol level | tlp = "WHITE"  tlp = "AMBER"',
                   snippet=True),
    CompletionItem("severity", 'severity = "$0"', "meta_key",
                   'Detection severity level | severity = "high"  severity = "critical"',
                   snippet=True),
]

_MODULE_NAMES = [
    "pe", "elf", "macho", "dotnet", "dex", "hash", "math",
    "time", "lnk", "string", "console", "crx",
]

# Module member completions — verified against YARA-X docs
_MODULE_MEMBERS = {
    # ── PE ────────────────────────────────────────────────────────
    "pe": [
        # Attributes
        CompletionItem("is_pe", "is_pe", "attribute",
                       "True if file is a valid PE | pe.is_pe"),
        CompletionItem("is_signed", "is_signed", "attribute",
                       "True if Authenticode sig present | pe.is_signed"),
        CompletionItem("machine", "machine", "attribute",
                       "CPU architecture enum | pe.machine == pe.MACHINE_AMD64"),
        CompletionItem("subsystem", "subsystem", "attribute",
                       "PE subsystem enum | pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI"),
        CompletionItem("os_version", "os_version", "attribute", "Version (major, minor)"),
        CompletionItem("subsystem_version", "subsystem_version", "attribute", "Version (major, minor)"),
        CompletionItem("image_version", "image_version", "attribute", "Version (major, minor)"),
        CompletionItem("linker_version", "linker_version", "attribute", "Version (major, minor)"),
        CompletionItem("opthdr_magic", "opthdr_magic", "attribute", "Optional header magic"),
        CompletionItem("characteristics", "characteristics", "attribute", "Characteristic flags"),
        CompletionItem("dll_characteristics", "dll_characteristics", "attribute", "DLL characteristic flags"),
        CompletionItem("timestamp", "timestamp", "attribute", "PE creation timestamp"),
        CompletionItem("image_base", "image_base", "attribute", "Base address in memory"),
        CompletionItem("checksum", "checksum", "attribute", "PE checksum value"),
        CompletionItem("base_of_code", "base_of_code", "attribute", "Code section base address"),
        CompletionItem("base_of_data", "base_of_data", "attribute", "Data section base address"),
        CompletionItem("entry_point", "entry_point", "attribute",
                       "Entry point file offset | $code at pe.entry_point"),
        CompletionItem("entry_point_raw", "entry_point_raw", "attribute",
                       "Entry point RVA (before offset conversion)"),
        CompletionItem("dll_name", "dll_name", "attribute",
                       "DLL export name | pe.dll_name contains \"malware\""),
        CompletionItem("export_timestamp", "export_timestamp", "attribute", "Export table timestamp"),
        CompletionItem("section_alignment", "section_alignment", "attribute", "Section alignment"),
        CompletionItem("file_alignment", "file_alignment", "attribute", "File alignment"),
        CompletionItem("loader_flags", "loader_flags", "attribute", "Loader flags"),
        CompletionItem("size_of_optional_header", "size_of_optional_header", "attribute", "Optional header size"),
        CompletionItem("size_of_code", "size_of_code", "attribute", "Code section size"),
        CompletionItem("size_of_initialized_data", "size_of_initialized_data", "attribute", "Initialized data size"),
        CompletionItem("size_of_uninitialized_data", "size_of_uninitialized_data", "attribute", "Uninitialized data size"),
        CompletionItem("size_of_image", "size_of_image", "attribute", "Total image size"),
        CompletionItem("size_of_headers", "size_of_headers", "attribute", "Headers size"),
        CompletionItem("size_of_stack_reserve", "size_of_stack_reserve", "attribute", "Stack reserve size"),
        CompletionItem("size_of_stack_commit", "size_of_stack_commit", "attribute", "Stack commit size"),
        CompletionItem("size_of_heap_reserve", "size_of_heap_reserve", "attribute", "Heap reserve size"),
        CompletionItem("size_of_heap_commit", "size_of_heap_commit", "attribute", "Heap commit size"),
        CompletionItem("pointer_to_symbol_table", "pointer_to_symbol_table", "attribute", "Symbol table offset"),
        CompletionItem("win32_version_value", "win32_version_value", "attribute", "Win32 version value"),
        CompletionItem("number_of_symbols", "number_of_symbols", "attribute", "Symbol count"),
        CompletionItem("number_of_rva_and_sizes", "number_of_rva_and_sizes", "attribute", "RVA/size entries"),
        CompletionItem("number_of_sections", "number_of_sections", "attribute",
                       "Section count | pe.number_of_sections > 5"),
        CompletionItem("number_of_imported_functions", "number_of_imported_functions", "attribute",
                       "Total imported functions | pe.number_of_imported_functions < 10"),
        CompletionItem("number_of_delayed_imported_functions", "number_of_delayed_imported_functions", "attribute", "Delayed import count"),
        CompletionItem("number_of_resources", "number_of_resources", "attribute", "Resource count"),
        CompletionItem("number_of_version_infos", "number_of_version_infos", "attribute", "Version info entries"),
        CompletionItem("number_of_imports", "number_of_imports", "attribute", "Import DLL count"),
        CompletionItem("number_of_delayed_imports", "number_of_delayed_imports", "attribute", "Delayed import DLL count"),
        CompletionItem("number_of_exports", "number_of_exports", "attribute", "Export count"),
        CompletionItem("number_of_signatures", "number_of_signatures", "attribute", "Signature count"),
        CompletionItem("version_info", "version_info", "attribute", "Version info dictionary"),
        CompletionItem("version_info_list", "version_info_list", "attribute", "Version info as KeyValue[]"),
        CompletionItem("rich_signature", "rich_signature", "attribute", "Rich header signature"),
        CompletionItem("pdb_path", "pdb_path", "attribute", "PDB debug path"),
        CompletionItem("sections", "sections", "attribute", "Section[]"),
        CompletionItem("data_directories", "data_directories", "attribute", "DirEntry[]"),
        CompletionItem("resource_timestamp", "resource_timestamp", "attribute", "Resource timestamp"),
        CompletionItem("resource_version", "resource_version", "attribute", "Resource version"),
        CompletionItem("resources", "resources", "attribute", "Resource[]"),
        CompletionItem("import_details", "import_details", "attribute", "Import[]"),
        CompletionItem("delayed_import_details", "delayed_import_details", "attribute", "Import[] (delayed)"),
        CompletionItem("export_details", "export_details", "attribute", "Export[]"),
        CompletionItem("signatures", "signatures", "attribute", "Signature[]"),
        CompletionItem("overlay", "overlay", "attribute", "Overlay (offset, size)"),
        # Functions
        CompletionItem("imports", "imports($0)", "function",
                       'Check if PE imports a function | pe.imports("kernel32.dll", "CreateFileA")',
                       snippet=True),
        CompletionItem("exports", "exports($0)", "function",
                       'Check if PE exports a name/ordinal | pe.exports("DllMain")  pe.exports(1)',
                       snippet=True),
        CompletionItem("exports_index", "exports_index($0)", "function",
                       'Get export index by name/ordinal | pe.exports_index("DllMain") == 0',
                       snippet=True),
        CompletionItem("imphash", "imphash()", "function",
                       'Import hash (Mandiant style) | pe.imphash() == "abc123..."'),
        CompletionItem("is_dll", "is_dll()", "function",
                       "True if IMAGE_FILE_DLL set | pe.is_dll()"),
        CompletionItem("is_32bit", "is_32bit()", "function",
                       "True if PE32 (not PE32+) | pe.is_32bit()"),
        CompletionItem("is_64bit", "is_64bit()", "function",
                       "True if PE32+ (64-bit) | pe.is_64bit()"),
        CompletionItem("rva_to_offset", "rva_to_offset($0)", "function",
                       "Convert RVA to file offset | uint32(pe.rva_to_offset(0x1000))",
                       snippet=True),
        CompletionItem("calculate_checksum", "calculate_checksum()", "function",
                       "Recompute PE checksum | pe.checksum != pe.calculate_checksum()"),
        CompletionItem("section_index", "section_index($0)", "function",
                       'Section index by name or RVA | pe.section_index(".text") == 0',
                       snippet=True),
        # Common constants
        CompletionItem("MACHINE_I386", "MACHINE_I386", "attribute", "Machine constant 0x014C"),
        CompletionItem("MACHINE_AMD64", "MACHINE_AMD64", "attribute", "Machine constant 0x8664"),
        CompletionItem("MACHINE_ARM", "MACHINE_ARM", "attribute", "Machine constant"),
        CompletionItem("MACHINE_ARM64", "MACHINE_ARM64", "attribute", "Machine constant"),
        CompletionItem("SUBSYSTEM_WINDOWS_GUI", "SUBSYSTEM_WINDOWS_GUI", "attribute", "Subsystem 2"),
        CompletionItem("SUBSYSTEM_WINDOWS_CUI", "SUBSYSTEM_WINDOWS_CUI", "attribute", "Subsystem 3"),
        CompletionItem("SUBSYSTEM_NATIVE", "SUBSYSTEM_NATIVE", "attribute", "Subsystem 1"),
        CompletionItem("RELOCS_STRIPPED", "RELOCS_STRIPPED", "attribute", "Characteristic 0x0001"),
        CompletionItem("EXECUTABLE_IMAGE", "EXECUTABLE_IMAGE", "attribute", "Characteristic 0x0002"),
        CompletionItem("LARGE_ADDRESS_AWARE", "LARGE_ADDRESS_AWARE", "attribute", "Characteristic 0x0020"),
        CompletionItem("DLL", "DLL", "attribute", "Characteristic 0x2000"),
        CompletionItem("DYNAMIC_BASE", "DYNAMIC_BASE", "attribute", "DLL characteristic 0x0040"),
        CompletionItem("NX_COMPAT", "NX_COMPAT", "attribute", "DLL characteristic 0x0100"),
        CompletionItem("HIGH_ENTROPY_VA", "HIGH_ENTROPY_VA", "attribute", "DLL characteristic 0x0020"),
        CompletionItem("GUARD_CF", "GUARD_CF", "attribute", "DLL characteristic 0x4000"),
        CompletionItem("IMPORT_STANDARD", "IMPORT_STANDARD", "attribute", "Import type 1"),
        CompletionItem("IMPORT_DELAYED", "IMPORT_DELAYED", "attribute", "Import type 2"),
        CompletionItem("IMPORT_ANY", "IMPORT_ANY", "attribute", "Import type 3"),
        CompletionItem("SECTION_CNT_CODE", "SECTION_CNT_CODE", "attribute", "Section characteristic"),
        CompletionItem("SECTION_MEM_EXECUTE", "SECTION_MEM_EXECUTE", "attribute", "Section characteristic"),
        CompletionItem("SECTION_MEM_READ", "SECTION_MEM_READ", "attribute", "Section characteristic"),
        CompletionItem("SECTION_MEM_WRITE", "SECTION_MEM_WRITE", "attribute", "Section characteristic"),
        CompletionItem("IMAGE_NT_OPTIONAL_HDR32_MAGIC", "IMAGE_NT_OPTIONAL_HDR32_MAGIC", "attribute", "Optional magic 0x10B"),
        CompletionItem("IMAGE_NT_OPTIONAL_HDR64_MAGIC", "IMAGE_NT_OPTIONAL_HDR64_MAGIC", "attribute", "Optional magic 0x20B"),
        CompletionItem("IMAGE_DIRECTORY_ENTRY_EXPORT", "IMAGE_DIRECTORY_ENTRY_EXPORT", "attribute", "Dir entry 0"),
        CompletionItem("IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_IMPORT", "attribute", "Dir entry 1"),
        CompletionItem("IMAGE_DIRECTORY_ENTRY_RESOURCE", "IMAGE_DIRECTORY_ENTRY_RESOURCE", "attribute", "Dir entry 2"),
        CompletionItem("IMAGE_DIRECTORY_ENTRY_SECURITY", "IMAGE_DIRECTORY_ENTRY_SECURITY", "attribute", "Dir entry 4"),
        CompletionItem("IMAGE_DIRECTORY_ENTRY_TLS", "IMAGE_DIRECTORY_ENTRY_TLS", "attribute", "Dir entry 10"),
        CompletionItem("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", "attribute", "Dir entry 15"),
        CompletionItem("RESOURCE_TYPE_ICON", "RESOURCE_TYPE_ICON", "attribute", "Resource type 3"),
        CompletionItem("RESOURCE_TYPE_VERSION", "RESOURCE_TYPE_VERSION", "attribute", "Resource type 16"),
        CompletionItem("RESOURCE_TYPE_MANIFEST", "RESOURCE_TYPE_MANIFEST", "attribute", "Resource type 24"),
    ],
    # ── ELF ───────────────────────────────────────────────────────
    "elf": [
        CompletionItem("type", "type", "attribute", "ELF file type enum"),
        CompletionItem("machine", "machine", "attribute", "Architecture enum"),
        CompletionItem("osabi", "osabi", "attribute", "OS/ABI enum"),
        CompletionItem("entry_point", "entry_point", "attribute", "Entry point address"),
        CompletionItem("sh_offset", "sh_offset", "attribute", "Section header table offset"),
        CompletionItem("sh_entry_size", "sh_entry_size", "attribute", "Section header entry size"),
        CompletionItem("ph_offset", "ph_offset", "attribute", "Program header table offset"),
        CompletionItem("ph_entry_size", "ph_entry_size", "attribute", "Program header entry size"),
        CompletionItem("number_of_sections", "number_of_sections", "attribute", "Number of sections"),
        CompletionItem("number_of_segments", "number_of_segments", "attribute", "Number of segments"),
        CompletionItem("symtab_entries", "symtab_entries", "attribute", "Symbol table entry count"),
        CompletionItem("dynsym_entries", "dynsym_entries", "attribute", "Dynamic symbol entry count"),
        CompletionItem("dynamic_section_entries", "dynamic_section_entries", "attribute", "Dynamic section entry count"),
        CompletionItem("sections", "sections", "attribute", "Section[]"),
        CompletionItem("segments", "segments", "attribute", "Segment[]"),
        CompletionItem("symtab", "symtab", "attribute", "Sym[] — symbol table"),
        CompletionItem("dynsym", "dynsym", "attribute", "Sym[] — dynamic symbols"),
        CompletionItem("dynamic", "dynamic", "attribute", "Dyn[] — dynamic section"),
        CompletionItem("import_md5", "import_md5()", "function", "MD5 hash of import table"),
        CompletionItem("telfhash", "telfhash()", "function", "TrendMicro telfhash"),
        # Common constants
        CompletionItem("ET_EXEC", "ET_EXEC", "attribute", "Executable file"),
        CompletionItem("ET_DYN", "ET_DYN", "attribute", "Shared object"),
        CompletionItem("ET_REL", "ET_REL", "attribute", "Relocatable file"),
        CompletionItem("EM_386", "EM_386", "attribute", "Intel 80386"),
        CompletionItem("EM_X86_64", "EM_X86_64", "attribute", "AMD x86-64"),
        CompletionItem("EM_ARM", "EM_ARM", "attribute", "ARM"),
        CompletionItem("EM_AARCH64", "EM_AARCH64", "attribute", "ARM AARCH64"),
        CompletionItem("PF_X", "PF_X", "attribute", "Segment executable 0x01"),
        CompletionItem("PF_W", "PF_W", "attribute", "Segment writable 0x02"),
        CompletionItem("PF_R", "PF_R", "attribute", "Segment readable 0x04"),
    ],
    # ── Math ──────────────────────────────────────────────────────
    "math": [
        CompletionItem("MEAN_BYTES", "MEAN_BYTES", "attribute",
                       "Constant 127.5 \u2014 expected mean of random bytes | math.deviation(0, filesize, math.MEAN_BYTES) > 50"),
        CompletionItem("entropy", "entropy($0)", "function",
                       "Shannon entropy (0.0\u20138.0) | math.entropy(0, filesize) > 7.5",
                       snippet=True),
        CompletionItem("mean", "mean($0)", "function",
                       "Arithmetic mean of bytes | math.mean(0, filesize) < 60",
                       snippet=True),
        CompletionItem("deviation", "deviation($0)", "function",
                       "Std deviation from expected mean | math.deviation(0, filesize, math.MEAN_BYTES) < 20",
                       snippet=True),
        CompletionItem("serial_correlation", "serial_correlation($0)", "function",
                       "Byte-to-byte correlation | math.serial_correlation(0, filesize) > 0.8",
                       snippet=True),
        CompletionItem("monte_carlo_pi", "monte_carlo_pi($0)", "function",
                       "Pi approximation (randomness test) | math.monte_carlo_pi(0, filesize) < 0.3",
                       snippet=True),
        CompletionItem("mode", "mode($0)", "function",
                       "Most frequent byte value | math.mode(0, filesize)",
                       snippet=True),
        CompletionItem("in_range", "in_range($0)", "function",
                       "Check value in [lo, hi] | math.in_range(math.entropy(0, filesize), 7.0, 8.0)",
                       snippet=True),
        CompletionItem("max", "max($0)", "function", "max(a, b) -> int", snippet=True),
        CompletionItem("min", "min($0)", "function", "min(a, b) -> int", snippet=True),
        CompletionItem("count", "count($0)", "function",
                       "Count occurrences of a byte | math.count(0x00, 0, filesize)",
                       snippet=True),
        CompletionItem("percentage", "percentage($0)", "function",
                       "Byte frequency as percentage | math.percentage(0x00, 0, filesize) > 50.0",
                       snippet=True),
        CompletionItem("to_number", "to_number($0)", "function",
                       "Convert bool to int | math.to_number(pe.is_dll())",
                       snippet=True),
        CompletionItem("to_string", "to_string($0)", "function",
                       "Convert int to string | math.to_string(pe.timestamp, 16)",
                       snippet=True),
        CompletionItem("abs", "abs($0)", "function", "Absolute value | math.abs(int_val)", snippet=True),
    ],
    # ── Hash ──────────────────────────────────────────────────────
    "hash": [
        CompletionItem("md5", "md5($0)", "function",
                       'MD5 hash of byte range | hash.md5(0, filesize) == "abc..."',
                       snippet=True),
        CompletionItem("sha1", "sha1($0)", "function",
                       'SHA-1 hash of byte range | hash.sha1(0, filesize)',
                       snippet=True),
        CompletionItem("sha256", "sha256($0)", "function",
                       'SHA-256 hash of byte range | hash.sha256(0, filesize) == "abc..."',
                       snippet=True),
        CompletionItem("checksum32", "checksum32($0)", "function",
                       "32-bit checksum of byte range | hash.checksum32(0, filesize)",
                       snippet=True),
        CompletionItem("crc32", "crc32($0)", "function",
                       "CRC32 of byte range | hash.crc32(0, filesize)",
                       snippet=True),
    ],
    # ── Dotnet ────────────────────────────────────────────────────
    "dotnet": [
        CompletionItem("is_dotnet", "is_dotnet", "attribute", "bool — file is .NET"),
        CompletionItem("module_name", "module_name", "attribute", "Module name string"),
        CompletionItem("version", "version", "attribute", "Version string"),
        CompletionItem("typelib", "typelib", "attribute", "Type library identifier"),
        CompletionItem("number_of_streams", "number_of_streams", "attribute", "Stream count"),
        CompletionItem("number_of_guids", "number_of_guids", "attribute", "GUID count"),
        CompletionItem("number_of_resources", "number_of_resources", "attribute", "Resource count"),
        CompletionItem("number_of_generic_parameters", "number_of_generic_parameters", "attribute", "Generic parameter count"),
        CompletionItem("number_of_classes", "number_of_classes", "attribute", "Class count"),
        CompletionItem("number_of_assembly_refs", "number_of_assembly_refs", "attribute", "Assembly reference count"),
        CompletionItem("number_of_modulerefs", "number_of_modulerefs", "attribute", "Module reference count"),
        CompletionItem("number_of_user_strings", "number_of_user_strings", "attribute", "User string count"),
        CompletionItem("number_of_constants", "number_of_constants", "attribute", "Constant count"),
        CompletionItem("number_of_field_offsets", "number_of_field_offsets", "attribute", "Field offset count"),
        CompletionItem("streams", "streams", "attribute", "Stream[]"),
        CompletionItem("guids", "guids", "attribute", "string[] — GUIDs"),
        CompletionItem("constants", "constants", "attribute", "string[]"),
        CompletionItem("assembly", "assembly", "attribute", "Assembly[]"),
        CompletionItem("assembly_refs", "assembly_refs", "attribute", "AssemblyRef[]"),
        CompletionItem("resources", "resources", "attribute", "Resource[]"),
        CompletionItem("classes", "classes", "attribute", "Class[]"),
        CompletionItem("field_offsets", "field_offsets", "attribute", "int[]"),
        CompletionItem("user_strings", "user_strings", "attribute", "string[]"),
        CompletionItem("modulerefs", "modulerefs", "attribute", "string[]"),
    ],
    # ── Macho ─────────────────────────────────────────────────────
    "macho": [
        CompletionItem("magic", "magic", "attribute", "Magic number"),
        CompletionItem("cputype", "cputype", "attribute", "CPU type"),
        CompletionItem("cpusubtype", "cpusubtype", "attribute", "CPU subtype"),
        CompletionItem("filetype", "filetype", "attribute", "File type"),
        CompletionItem("ncmds", "ncmds", "attribute", "Number of load commands"),
        CompletionItem("sizeofcmds", "sizeofcmds", "attribute", "Size of load commands"),
        CompletionItem("flags", "flags", "attribute", "Flags"),
        CompletionItem("number_of_segments", "number_of_segments", "attribute", "Segment count"),
        CompletionItem("dynamic_linker", "dynamic_linker", "attribute", "Dynamic linker path"),
        CompletionItem("entry_point", "entry_point", "attribute", "Entry point"),
        CompletionItem("stack_size", "stack_size", "attribute", "Stack size"),
        CompletionItem("source_version", "source_version", "attribute", "Source version"),
        CompletionItem("uuid", "uuid", "attribute", "UUID string"),
        CompletionItem("symtab", "symtab", "attribute", "Symbol table"),
        CompletionItem("dysymtab", "dysymtab", "attribute", "Dynamic symbol table"),
        CompletionItem("segments", "segments", "attribute", "Segment[]"),
        CompletionItem("dylibs", "dylibs", "attribute", "Dylib[]"),
        CompletionItem("rpaths", "rpaths", "attribute", "string[] — runtime paths"),
        CompletionItem("entitlements", "entitlements", "attribute", "string[]"),
        CompletionItem("certificates", "certificates", "attribute", "Certificate[]"),
        CompletionItem("exports", "exports", "attribute", "string[] — exported symbols"),
        CompletionItem("imports", "imports", "attribute", "string[] — imported symbols"),
        CompletionItem("build_version", "build_version", "attribute", "BuildVersion"),
        CompletionItem("min_version", "min_version", "attribute", "MinVersion"),
        CompletionItem("fat_magic", "fat_magic", "attribute", "Fat header magic"),
        CompletionItem("nfat_arch", "nfat_arch", "attribute", "Number of fat architectures"),
        CompletionItem("fat_arch", "fat_arch", "attribute", "FatArch[]"),
        CompletionItem("file", "file", "attribute", "File[] — fat binary files"),
        CompletionItem("file_index_for_arch", "file_index_for_arch($0)", "function", "Index by CPU type", snippet=True),
        CompletionItem("entry_point_for_arch", "entry_point_for_arch($0)", "function", "Entry point by CPU type", snippet=True),
        CompletionItem("has_entitlement", "has_entitlement($0)", "function", "Check entitlement string", snippet=True),
        CompletionItem("has_dylib", "has_dylib($0)", "function", "Check dynamic library name", snippet=True),
        CompletionItem("has_rpath", "has_rpath($0)", "function", "Check runtime path", snippet=True),
        CompletionItem("has_import", "has_import($0)", "function", "Check import symbol", snippet=True),
        CompletionItem("has_export", "has_export($0)", "function", "Check export symbol", snippet=True),
        CompletionItem("dylib_hash", "dylib_hash()", "function", "MD5 of dylibs"),
        CompletionItem("entitlement_hash", "entitlement_hash()", "function", "SHA256 of entitlements"),
        CompletionItem("export_hash", "export_hash()", "function", "MD5 of exports"),
        CompletionItem("import_hash", "import_hash()", "function", "MD5 of imports"),
        CompletionItem("symhash", "symhash()", "function", "MD5 of symbols"),
    ],
    # ── DEX ───────────────────────────────────────────────────────
    "dex": [
        CompletionItem("is_dex", "is_dex", "attribute", "bool — file is DEX"),
        CompletionItem("header", "header", "attribute", "DexHeader"),
        CompletionItem("strings", "strings", "attribute", "string[] — all strings"),
        CompletionItem("types", "types", "attribute", "string[] — all types"),
        CompletionItem("protos", "protos", "attribute", "ProtoItem[]"),
        CompletionItem("fields", "fields", "attribute", "FieldItem[]"),
        CompletionItem("methods", "methods", "attribute", "MethodItem[]"),
        CompletionItem("class_defs", "class_defs", "attribute", "ClassItem[]"),
        CompletionItem("map_list", "map_list", "attribute", "MapList"),
        CompletionItem("checksum", "checksum()", "function", "Adler-32 checksum"),
        CompletionItem("signature", "signature()", "function", "SHA-1 signature"),
        CompletionItem("contains_string", "contains_string($0)", "function", "Search for string", snippet=True),
        CompletionItem("contains_method", "contains_method($0)", "function", "Search for method", snippet=True),
        CompletionItem("contains_class", "contains_class($0)", "function", "Search for class", snippet=True),
    ],
    # ── Time ──────────────────────────────────────────────────────
    "time": [
        CompletionItem("now", "now()", "function", "Current Unix timestamp"),
    ],
    # ── LNK (YARA-X specific) ────────────────────────────────────
    "lnk": [
        CompletionItem("is_lnk", "is_lnk", "attribute", "bool — file is LNK"),
        CompletionItem("name", "name", "attribute", "Shortcut description"),
        CompletionItem("creation_time", "creation_time", "attribute", "Creation timestamp"),
        CompletionItem("access_time", "access_time", "attribute", "Last access timestamp"),
        CompletionItem("write_time", "write_time", "attribute", "Last modification timestamp"),
        CompletionItem("file_size", "file_size", "attribute", "Target file size"),
        CompletionItem("file_attributes", "file_attributes", "attribute", "Target file attributes"),
        CompletionItem("icon_location", "icon_location", "attribute", "Icon location path"),
        CompletionItem("icon_index", "icon_index", "attribute", "Icon index"),
        CompletionItem("show_command", "show_command", "attribute", "Expected window state"),
        CompletionItem("drive_type", "drive_type", "attribute", "Drive type enum"),
        CompletionItem("drive_serial_number", "drive_serial_number", "attribute", "Volume serial number"),
        CompletionItem("volume_label", "volume_label", "attribute", "Volume label"),
        CompletionItem("local_base_path", "local_base_path", "attribute", "Base path for target"),
        CompletionItem("common_path_suffix", "common_path_suffix", "attribute", "Path suffix"),
        CompletionItem("relative_path", "relative_path", "attribute", "Relative path to target"),
        CompletionItem("working_dir", "working_dir", "attribute", "Working directory"),
        CompletionItem("cmd_line_args", "cmd_line_args", "attribute", "Command-line arguments"),
        CompletionItem("overlay_size", "overlay_size", "attribute", "Overlay size in bytes"),
        CompletionItem("overlay_offset", "overlay_offset", "attribute", "Overlay start offset"),
        CompletionItem("tracker_data", "tracker_data", "attribute", "TrackerData"),
    ],
    # ── String (YARA-X specific) ─────────────────────────────────
    "string": [
        CompletionItem("to_int", "to_int($0)", "function", "to_int(string[, base]) -> int", snippet=True),
        CompletionItem("length", "length($0)", "function", "length(string) -> int", snippet=True),
    ],
    # ── Console ───────────────────────────────────────────────────
    "console": [
        CompletionItem("log", "log($0)", "function", "Log value (string/int/float/bool)", snippet=True),
        CompletionItem("hex", "hex($0)", "function", "Log integer as hex", snippet=True),
    ],
    # ── CRX (YARA-X specific) ────────────────────────────────────
    "crx": [
        CompletionItem("is_crx", "is_crx", "attribute", "bool — file is CRX"),
        CompletionItem("crx_version", "crx_version", "attribute", "CRX format version"),
        CompletionItem("header_size", "header_size", "attribute", "Header size"),
        CompletionItem("id", "id", "attribute", "Extension identifier"),
        CompletionItem("version", "version", "attribute", "Extension version"),
        CompletionItem("name", "name", "attribute", "Extension name"),
        CompletionItem("description", "description", "attribute", "Extension description"),
        CompletionItem("raw_name", "raw_name", "attribute", "Unprocessed name"),
        CompletionItem("raw_description", "raw_description", "attribute", "Unprocessed description"),
        CompletionItem("homepage_url", "homepage_url", "attribute", "Homepage URL"),
        CompletionItem("permissions", "permissions", "attribute", "string[] — permissions"),
        CompletionItem("host_permissions", "host_permissions", "attribute", "string[]"),
        CompletionItem("optional_permissions", "optional_permissions", "attribute", "string[]"),
        CompletionItem("optional_host_permissions", "optional_host_permissions", "attribute", "string[]"),
        CompletionItem("signatures", "signatures", "attribute", "Signature[]"),
        CompletionItem("permhash", "permhash()", "function", "SHA256 permissions hash"),
    ],
}


# ── Completion Engine ─────────────────────────────────────────────

class CompletionEngine:
    """Generate context-aware completion items and fuzzy-filter by prefix."""

    def __init__(self):
        self._module_names = _MODULE_NAMES

    def get_completions(self, text: str, cursor_pos: int) -> List[CompletionItem]:
        """Return context-aware completion items for the given cursor position."""
        # Determine context by walking backwards from cursor
        before = text[:cursor_pos]
        line_start = before.rfind("\n") + 1
        current_line = before[line_start:]

        # 1. After 'import "' → module names
        if re.search(r'import\s+"[a-z]*$', before):
            prefix = re.search(r'"([a-z]*)$', before)
            prefix_text = prefix.group(1) if prefix else ""
            items = [CompletionItem(m, m + '"', "module", f"YARA module: {m}")
                     for m in self._module_names]
            return self._filter(items, prefix_text)

        # 2. After module_name. → module members
        dot_match = re.search(r'\b(' + '|'.join(self._module_names) + r')\.\w*$', before)
        if dot_match:
            module_name = dot_match.group(1)
            after_dot = before[dot_match.start() + len(module_name) + 1:]
            members = _MODULE_MEMBERS.get(module_name, [])
            return self._filter(members, after_dot)

        # 3. Detect section context
        section = self._detect_section(before)

        # 4. In meta: → meta keys
        if section == "meta":
            stripped = current_line.strip()
            # Only offer keys at start of line (not after =)
            if "=" not in current_line:
                return self._filter(_META_KEYS, stripped)

        # 5. In strings: after closing quote/brace → modifiers
        if section == "strings":
            # Check if we're after a string definition (after " or } on the line)
            if re.search(r'(?:"|\'|\})\s+\w*$', current_line):
                word = re.search(r'\b(\w*)$', current_line)
                prefix_text = word.group(1) if word else ""
                return self._filter(_STRING_MODIFIERS, prefix_text)

        # 6. In condition: → variables + keywords + builtins
        if section == "condition":
            word = re.search(r'[\$#@!]?\w*$', current_line)
            prefix_text = word.group(0) if word else ""

            items: List[CompletionItem] = []

            # Add $variables parsed from strings section
            variables = self._extract_string_variables(text)
            items.extend(variables)

            # Add condition keywords + builtins
            items.extend(_CONDITION_KEYWORDS)

            # Add module names as completable
            for m in self._module_names:
                items.append(CompletionItem(m, m + ".", "module", f"Module: {m}"))

            return self._filter(items, prefix_text)

        # 7. Default (top-level, outside any section) → only top-level
        # keywords like rule/import/include/private/global.  Don't dump
        # the massive condition keyword list here — it's irrelevant
        # outside a condition: block and just creates noise.
        word = re.search(r'\b(\w*)$', current_line)
        prefix_text = word.group(1) if word else ""
        return self._filter(_YARA_KEYWORDS, prefix_text)

    def _detect_section(self, before: str) -> Optional[str]:
        """Walk backwards to find which section the cursor is in."""
        # Find the last section header
        last_meta = before.rfind("meta:")
        last_strings = before.rfind("strings:")
        last_condition = before.rfind("condition:")

        # Find the last rule opening brace to scope sections
        last_rule_brace = before.rfind("{")

        positions = {
            "meta": last_meta,
            "strings": last_strings,
            "condition": last_condition,
        }
        # Filter to sections after the last rule brace
        valid = {k: v for k, v in positions.items()
                 if v > last_rule_brace and v >= 0}

        if not valid:
            return None
        return max(valid, key=valid.get)

    def _extract_string_variables(self, text: str) -> List[CompletionItem]:
        """Parse $variable names from strings: sections."""
        items = []
        seen = set()
        for m in re.finditer(r'(\$[A-Za-z_][A-Za-z0-9_]*)\s*=', text):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                items.append(CompletionItem(name, name, "variable", "String variable"))
                # Also add #, @, ! variants
                base = name[1:]  # strip $
                items.append(CompletionItem(f"#{base}", f"#{base}", "variable",
                                            f"Count of {name}"))
                items.append(CompletionItem(f"@{base}", f"@{base}", "variable",
                                            f"Offset of {name}"))
                items.append(CompletionItem(f"!{base}", f"!{base}", "variable",
                                            f"Length of {name} match"))
        return items

    @staticmethod
    def _filter(items: List[CompletionItem], prefix: str) -> List[CompletionItem]:
        """Filter items by prefix match (case-insensitive).

        Only prefix and contains matching — no subsequence matching,
        which produces too much noise (e.g. "fi" matching "float32"
        via f...i).  Exact matches where the label equals the prefix
        are excluded since there's nothing left to complete.
        """
        if not prefix:
            return items
        prefix_lower = prefix.lower()
        scored = []
        for item in items:
            label_lower = item.label.lower()
            if label_lower == prefix_lower and not item.snippet:
                # Already fully typed — skip (nothing to gain).
                # Snippets are kept because they expand a template.
                continue
            elif label_lower == prefix_lower and item.snippet:
                # Exact match but it's a snippet — rank highest
                scored.append((-1, len(label_lower), item))
            elif label_lower.startswith(prefix_lower):
                # Prefix match — shorter labels rank higher
                scored.append((0, len(label_lower), item))
            elif prefix_lower in label_lower:
                # Contains match
                scored.append((1, len(label_lower), item))
        scored.sort(key=lambda x: (x[0], x[1], x[2].label))
        return [item for _, _, item in scored]


# ── Completion Popup ──────────────────────────────────────────────

class CompletionPopup(QWidget):
    """Frameless popup showing completion items with detail label."""

    completion_selected = Signal(str, bool)  # insert_text, is_snippet

    MAX_VISIBLE = 10

    def __init__(self, editor: QTextEdit, parent=None):
        super().__init__(parent or editor, Qt.WindowType.ToolTip)
        self._editor = editor
        self._prefix = ""
        self._items: List[CompletionItem] = []
        self._navigated = False  # True once user presses Up/Down in the list

        layout = QVBoxLayout(self)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.setSpacing(0)

        self._list = QListWidget()
        self._list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._list.currentRowChanged.connect(self._on_row_changed)
        self._list.itemDoubleClicked.connect(self._accept_current)
        layout.addWidget(self._list)

        self._detail = QLabel()
        self._detail.setWordWrap(True)
        self._detail.setTextFormat(Qt.TextFormat.RichText)
        self._detail.setContentsMargins(6, 4, 6, 4)
        self._detail.setStyleSheet("font-size: 9pt;")
        layout.addWidget(self._detail)

        self.setFixedWidth(420)
        self.hide()

    def set_theme_manager(self, theme_manager):
        """Apply theme colours to popup."""
        if not theme_manager or not theme_manager.current_theme:
            return
        c = theme_manager.current_theme.colors
        bg = getattr(c, "surface", getattr(c, "editor_background", "#1e1e1e"))
        text = getattr(c, "text_primary", getattr(c, "editor_text", "#cccccc"))
        sel_bg = getattr(c, "selection_background", "#264f78")
        sel_text = getattr(c, "selection_text", "#ffffff")
        border = getattr(c, "primary", "#3d3d3d")
        self.setStyleSheet(f"""
            CompletionPopup {{
                background: {bg};
                border: 1px solid {border};
            }}
            QListWidget {{
                background: {bg};
                color: {text};
                border: none;
                outline: none;
            }}
            QListWidget::item:selected {{
                background: {sel_bg};
                color: {sel_text};
            }}
            QLabel {{
                color: {text};
                background: {bg};
            }}
        """)

    def show_completions(self, items: List[CompletionItem], prefix: str):
        """Populate and show the popup."""
        self._items = items
        self._prefix = prefix
        self._navigated = False
        self._list.clear()

        if not items:
            self.hide()
            return

        for item in items:
            li = QListWidgetItem(f"{item.icon}  {item.label}")
            li.setData(Qt.ItemDataRole.UserRole, item)
            self._list.addItem(li)

        self._list.setCurrentRow(0)
        row_h = self._list.sizeHintForRow(0) or 20
        visible_rows = min(len(items), self.MAX_VISIBLE)
        self._list.setFixedHeight(row_h * visible_rows + 4)
        self.adjustSize()

        self._position_popup()
        self.show()
        self.raise_()

    def _position_popup(self):
        """Position below cursor, clamped to screen edges."""
        cursor = self._editor.textCursor()
        rect = self._editor.cursorRect(cursor)
        global_pos = self._editor.mapToGlobal(QPoint(rect.left(), rect.bottom() + 2))

        screen = QApplication.screenAt(global_pos)
        if screen:
            screen_geo = screen.availableGeometry()
            # Clamp horizontal
            if global_pos.x() + self.width() > screen_geo.right():
                global_pos.setX(screen_geo.right() - self.width())
            # Flip above if too low
            if global_pos.y() + self.height() > screen_geo.bottom():
                global_pos.setY(self._editor.mapToGlobal(
                    QPoint(rect.left(), rect.top())).y() - self.height() - 2)

        self.move(global_pos)

    def _on_row_changed(self, row: int):
        if 0 <= row < len(self._items):
            item = self._items[row]
            self._detail.setText(self._format_detail(item))
        else:
            self._detail.setText("")

    @staticmethod
    def _format_detail(item: CompletionItem) -> str:
        """Render the detail pane as rich HTML with description + example."""
        import html as _html
        parts = [f"<b>{_html.escape(item.kind)}</b>"]
        if item.detail:
            # Split on " | " — text before is description, after is example
            if " | " in item.detail:
                desc, example = item.detail.split(" | ", 1)
                parts.append(f" &mdash; {_html.escape(desc)}")
                parts.append(
                    f'<br><code style="color:#6a9955;">'
                    f'{_html.escape(example)}</code>')
            else:
                parts.append(f" &mdash; {_html.escape(item.detail)}")
        return "".join(parts)

    def _accept_current(self, *_args):
        row = self._list.currentRow()
        if 0 <= row < len(self._items):
            item = self._items[row]
            self.completion_selected.emit(item.insert_text, item.snippet)
        self.hide()

    def handle_key(self, event: QKeyEvent) -> bool:
        """Handle key events when popup is visible. Returns True if consumed."""
        if not self.isVisible():
            return False

        key = event.key()

        if key == Qt.Key.Key_Escape:
            self.hide()
            return True

        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self._accept_current()
            return True

        # Tab only accepts if user has explicitly navigated the list
        if key == Qt.Key.Key_Tab:
            if self._navigated:
                self._accept_current()
                return True
            # Otherwise dismiss and let Tab indent normally
            self.hide()
            return False

        if key == Qt.Key.Key_Down:
            row = self._list.currentRow()
            if row < self._list.count() - 1:
                self._list.setCurrentRow(row + 1)
            self._navigated = True
            return True

        if key == Qt.Key.Key_Up:
            row = self._list.currentRow()
            if row > 0:
                self._list.setCurrentRow(row - 1)
            self._navigated = True
            return True

        return False

    @property
    def is_visible(self) -> bool:
        return self.isVisible()
