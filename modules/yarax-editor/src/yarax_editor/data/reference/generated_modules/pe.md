# pe — YARA-X 1.20.0

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

Generated from the official protobuf definitions and Rust exports. Availability depends on the engine build and field feature restrictions.

## pe.PE

### is_pe

Type: bool

True if the file is a valid PE binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### machine

Type: pe.Machine

Target architecture of the executable (e.g., x86, x64, ARM).

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### subsystem

Type: pe.Subsystem

Subsystem required to run this binary (e.g., GUI, CUI).

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### os_version

Type: pe.Version

Minimum operating system version required to run the binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### subsystem_version

Type: pe.Version

Minimum subsystem version required to run the binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### image_version

Type: pe.Version

User-defined version of the binary image.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### linker_version

Type: pe.Version

Version of the linker used to generate the binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### opthdr_magic

Type: pe.OptionalMagic

Magic number used to identify the optional header structure.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### characteristics

Type: uint32

Bitwise flags indicating attributes of the file (e.g., executable, DLL).

Field annotations:
```json
{
  "fmt": "flags:Characteristics"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### dll_characteristics

Type: uint32

Bitwise flags indicating DLL characteristics (e.g., ASLR, DEP).

Field annotations:
```json
{
  "fmt": "flags:DllCharacteristics"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### timestamp

Type: uint32

Creation timestamp of the image, stored as a Unix epoch time.

Field annotations:
```json
{
  "fmt": "t"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### image_base

Type: uint64

Preferred load address of the image when placed in memory.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### checksum

Type: uint32

Checksum of the image file.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### base_of_code

Type: uint32

Relative virtual address (RVA) of the beginning of the code section.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### base_of_data

Type: uint32

Relative virtual address (RVA) of the beginning of the data section.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### entry_point

Type: uint32

Entry point as a file offset.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### entry_point_raw

Type: uint32

Entry point as it appears in the PE header (RVA).

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### dll_name

Type: string

Filename of the dynamic-link library, if the image is a DLL.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### export_timestamp

Type: uint32

Export table timestamp, stored as a Unix epoch time.

Field annotations:
```json
{
  "fmt": "t"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### section_alignment

Type: uint32

Alignment factor used for sections loaded in memory (usually 4096 bytes).

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### file_alignment

Type: uint32

Alignment factor used for raw section data on disk (usually 512 bytes).

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### loader_flags

Type: uint32

Flags used by obsolete loaders.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### size_of_optional_header

Type: uint32

Size of the optional header structure in bytes.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### size_of_code

Type: uint32

Total size of all sections containing executable code.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### size_of_initialized_data

Type: uint32

Total size of all sections containing initialized data.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### size_of_uninitialized_data

Type: uint32

Total size of all sections containing uninitialized data (BSS).

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### size_of_image

Type: uint32

Overall size of the image loaded in memory, including all headers.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### size_of_headers

Type: uint32

Combined size of all headers up to the first section.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### size_of_stack_reserve

Type: uint64

Total amount of virtual memory reserved for the stack.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### size_of_stack_commit

Type: uint64

Initial amount of physical memory committed for the stack.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### size_of_heap_reserve

Type: uint64

Total amount of virtual memory reserved for the default heap.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### size_of_heap_commit

Type: uint64

Initial amount of physical memory committed for the default heap.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### pointer_to_symbol_table

Type: uint32

File offset pointing to the COFF symbol table.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### win32_version_value

Type: uint32

Reserved field, must be set to zero.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_symbols

Type: uint32

Number of entries found in the COFF symbol table.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_rva_and_sizes

Type: uint32

Number of entries present in the data directories array.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_sections

Type: uint32

Number of sections in the PE file.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `pe.sections.len()` instead",
    "replacement": "sections.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_imported_functions

Type: uint64

Number of imported functions across all imported libraries.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_delayed_imported_functions

Type: uint64

Number of delayed imported functions across all delayed libraries.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_resources

Type: uint64

Number of resources contained within the file.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `pe.resources.len()` instead",
    "replacement": "resources.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_version_infos

Type: uint64

Number of string-value pairs within the version info resource.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_imports

Type: uint64

Number of imported libraries.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_delayed_imports

Type: uint64

Number of delayed imported libraries.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_exports

Type: uint64

Number of exported symbols.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_signatures

Type: uint64

Number of digital signatures found in the file.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `pe.signatures.len()` instead",
    "replacement": "signatures.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### version_info

Type: array of pe.PE.VersionInfoEntry

Map representation of file version information attributes.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### version_info_list

Type: array of pe.KeyValue

List containing version information attributes as key-value elements.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### rich_signature

Type: pe.RichSignature

Rich header signature containing toolchain usage information.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### pdb_path

Type: bytes

File path referencing the associated PDB symbol file.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### sections

Type: array of pe.Section

Collection of sections making up the binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### data_directories

Type: array of pe.DirEntry

Standard data directories array (e.g., Imports, Exports, Resources).

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### resource_timestamp

Type: uint64

Unix epoch timestamp of the resource directory.

Field annotations:
```json
{
  "fmt": "t"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### resource_version

Type: pe.Version

Version structure for the resource directory.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### resources

Type: array of pe.Resource

Individual resources defined within the binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### import_details

Type: array of pe.Import

Standard library and function import descriptions.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### delayed_import_details

Type: array of pe.Import

Delayed library and function import descriptions.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### export_details

Type: array of pe.Export

Exported functions and symbol descriptions.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### is_signed

Type: bool

True if the executable contains a recognized digital signature.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### signatures

Type: array of pe.Signature

Set of digital signatures extracted from the file.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### overlay

Type: pe.Overlay

Information regarding trailing data not mapped by sections.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RELOCS_STRIPPED

Type: integer

Relocation info stripped from file.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### EXECUTABLE_IMAGE

Type: integer

File is executable (i.e. no unresolved external references).

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### LINE_NUMS_STRIPPED

Type: integer

Line numbers stripped from file.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### LOCAL_SYMS_STRIPPED

Type: integer

Local symbols stripped from file.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### AGGRESIVE_WS_TRIM

Type: integer

Aggressively trim working set

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### LARGE_ADDRESS_AWARE

Type: integer

App can handle >2gb addresses

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### BYTES_REVERSED_LO

Type: integer

Bytes of machine word are reversed.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_32BIT

Type: integer

32 bit word machine.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### DEBUG_STRIPPED

Type: integer

Debugging info stripped from file in .DBG file

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### REMOVABLE_RUN_FROM_SWAP

Type: integer

If Image is on removable media, copy and run from the swap file.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### NET_RUN_FROM_SWAP

Type: integer

If Image is on Net, copy and run from the swap file.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SYSTEM

Type: integer

System File.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### DLL

Type: integer

File is a DLL.s

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### UP_SYSTEM_ONLY

Type: integer

File should only be run on a UP machine

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### BYTES_REVERSED_HI

Type: integer

Bytes of machine word are reversed.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_EXPORT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_IMPORT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_RESOURCE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_EXCEPTION

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_SECURITY

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_BASERELOC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_DEBUG

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_COPYRIGHT

Type: integer

IMAGE_DIRECTORY_ENTRY_COPYRIGHT and IMAGE_DIRECTORY_ENTRY_ARCHITECTURE
 have the same value (7).

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_ARCHITECTURE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_GLOBALPTR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_TLS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_IAT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### HIGH_ENTROPY_VA

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### DYNAMIC_BASE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### FORCE_INTEGRITY

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### NX_COMPAT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### NO_ISOLATION

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### NO_SEH

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### NO_BIND

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### APPCONTAINER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### WDM_DRIVER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### GUARD_CF

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### TERMINAL_SERVER_AWARE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMPORT_STANDARD

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMPORT_DELAYED

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMPORT_ANY

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_UNKNOWN

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_ALPHA

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_ALPHA64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_AM33

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_AMD64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_ARM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_ARM64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_ARM64EC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_ARM64X

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_ARMNT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_AXP64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_EBC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_I386

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_IA64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_LOONGARCH32

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_LOONGARCH64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_M32R

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_MIPS16

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_MIPSFPU

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_MIPSFPU16

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_POWERPC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_POWERPCFP

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_R3000BE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_R3000

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_R4000

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_R10000

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_RISCV32

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_RISCV64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_RISCV128

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_SH3

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_SH3DSP

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_SH4

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_SH5

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_THUMB

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_WCEMIPSV2

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_NT_OPTIONAL_HDR32_MAGIC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_NT_OPTIONAL_HDR64_MAGIC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_ROM_OPTIONAL_HDR_MAGIC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_CURSOR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_BITMAP

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_ICON

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_MENU

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_DIALOG

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_STRING

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_FONTDIR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_FONT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_ACCELERATOR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_RCDATA

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_MESSAGETABLE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_GROUP_CURSOR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_GROUP_ICON

Type: integer

13 is missing

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_VERSION

Type: integer

15 is missing

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_DLGINCLUDE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_PLUGPLAY

Type: integer

18 is missing

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_VXD

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_ANICURSOR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_ANIICON

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_HTML

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_MANIFEST

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_NO_PAD

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_CNT_CODE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_CNT_INITIALIZED_DATA

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_CNT_UNINITIALIZED_DATA

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_LNK_OTHER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_LNK_INFO

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_LNK_REMOVE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_LNK_COMDAT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_NO_DEFER_SPEC_EXC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_GPREL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_ALIGN_1BYTES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_ALIGN_2BYTES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_ALIGN_4BYTES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_ALIGN_8BYTES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_ALIGN_16BYTES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_ALIGN_32BYTES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_ALIGN_64BYTES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_ALIGN_128BYTES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_ALIGN_256BYTES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_ALIGN_512BYTES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_ALIGN_1024BYTES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_ALIGN_2048BYTES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_ALIGN_4096BYTES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_ALIGN_8192BYTES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_ALIGN_MASK

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_LNK_NRELOC_OVFL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_MEM_DISCARDABLE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_MEM_NOT_CACHED

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_MEM_NOT_PAGED

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_MEM_SHARED

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_MEM_EXECUTE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_MEM_READ

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_MEM_WRITE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SECTION_SCALE_INDEX

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_UNKNOWN

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_NATIVE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_WINDOWS_GUI

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_WINDOWS_CUI

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_OS2_CUI

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_POSIX_CUI

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_NATIVE_WINDOWS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_WINDOWS_CE_GUI

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_EFI_APPLICATION

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_EFI_RUNTIME_DRIVER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_EFI_ROM_IMAGE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_XBOX

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_WINDOWS_BOOT_APPLICATION

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.Machine

### MACHINE_UNKNOWN

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_ALPHA

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_ALPHA64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_AM33

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_AMD64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_ARM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_ARM64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_ARM64EC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_ARM64X

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_ARMNT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_AXP64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_EBC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_I386

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_IA64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_LOONGARCH32

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_LOONGARCH64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_M32R

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_MIPS16

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_MIPSFPU

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_MIPSFPU16

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_POWERPC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_POWERPCFP

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_R3000BE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_R3000

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_R4000

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_R10000

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_RISCV32

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_RISCV64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_RISCV128

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_SH3

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_SH3DSP

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_SH4

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_SH5

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_THUMB

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### MACHINE_WCEMIPSV2

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.Subsystem

### SUBSYSTEM_UNKNOWN

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_NATIVE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_WINDOWS_GUI

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_WINDOWS_CUI

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_OS2_CUI

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_POSIX_CUI

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_NATIVE_WINDOWS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_WINDOWS_CE_GUI

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_EFI_APPLICATION

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_EFI_RUNTIME_DRIVER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_EFI_ROM_IMAGE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_XBOX

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### SUBSYSTEM_WINDOWS_BOOT_APPLICATION

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.Version

### major

Type: uint32

Major version number.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### minor

Type: uint32

Minor version number.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.OptionalMagic

### IMAGE_NT_OPTIONAL_HDR32_MAGIC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_NT_OPTIONAL_HDR64_MAGIC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### IMAGE_ROM_OPTIONAL_HDR_MAGIC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.PE.VersionInfoEntry

### key

Type: string

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### value

Type: string

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.KeyValue

### key

Type: string

Key identifying the entry.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### value

Type: string

String value associated with the key.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.RichSignature

### offset

Type: uint32

Relative file offset marking the start of the Rich signature.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### length

Type: uint32

Total length in bytes of the Rich signature block.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### key

Type: uint32

Numerical XOR key utilized to decrypt the Rich signature.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### raw_data

Type: bytes

Obfuscated binary bytes of the Rich signature.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### clear_data

Type: bytes

Cleartext decrypted bytes of the Rich signature.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### tools

Type: array of pe.RichTool

Individual tools and build utilities referenced in the signature.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.RichTool

### toolid

Type: uint32

Identifier corresponding to the compilation tool.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### version

Type: uint32

Internal version of the tool.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### times

Type: uint32

Number of times the tool was invoked to build objects in the final binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.Section

### name

Type: bytes

Section name as listed in the section table. The data type is `bytes`
 instead of `string` so that it can accommodate invalid UTF-8 content. The
 length is 8 bytes at most.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### full_name

Type: bytes

For section names longer than 8 bytes, the name in the section table (and
 in the `name` field) contains a forward slash (/) followed by an ASCII
 representation of a decimal number that is an offset into the string table.
 (examples: "/4", "/123") This mechanism is described in the MSDN and used
 by GNU compilers.

 When this scenario occurs, the `full_name` field holds the actual section
 name. In all other cases, it simply duplicates the content of the `name`
 field.

 See: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header#members

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### characteristics

Type: uint32

Characteristics and access attributes of the section.

Field annotations:
```json
{
  "fmt": "flags:SectionCharacteristics"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### raw_data_size

Type: uint32

Physical size of the section stored on disk.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### raw_data_offset

Type: uint32

File offset to the section data on disk.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### virtual_address

Type: uint32

Virtual address of the section loaded in memory, relative to the image base.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### virtual_size

Type: uint32

Total virtual size occupied by the section in memory.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### pointer_to_relocations

Type: uint32

File pointer referencing the section's relocation entries.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### pointer_to_line_numbers

Type: uint32

File pointer referencing the section's line-number entries.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_relocations

Type: uint32

Total count of relocation records for the section.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_line_numbers

Type: uint32

Total count of line-number records for the section.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.DirEntry

### virtual_address

Type: uint32

Relative virtual address of the data directory structure.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### size

Type: uint32

Size in bytes of the data directory structure.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.Resource

### length

Type: uint32

Size of the resource content in bytes.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### rva

Type: uint32

Relative virtual address (RVA) of the resource data.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### offset

Type: uint32

File offset pointing to the resource data.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### type

Type: pe.ResourceType

Standard resource type classification (e.g., ICON, VERSION).

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### id

Type: uint32

Unique numeric identifier of the resource.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### language

Type: uint32

Language code assigned to the resource.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### type_string

Type: bytes

Text representation of the resource type for custom classifications.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### name_string

Type: bytes

Text representation of the resource name.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### language_string

Type: bytes

Text representation of the resource language.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.ResourceType

### RESOURCE_TYPE_CURSOR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_BITMAP

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_ICON

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_MENU

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_DIALOG

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_STRING

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_FONTDIR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_FONT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_ACCELERATOR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_RCDATA

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_MESSAGETABLE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_GROUP_CURSOR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_GROUP_ICON

Type: integer

13 is missing

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_VERSION

Type: integer

15 is missing

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_DLGINCLUDE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_PLUGPLAY

Type: integer

18 is missing

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_VXD

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_ANICURSOR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_ANIICON

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_HTML

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### RESOURCE_TYPE_MANIFEST

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.Import

### library_name

Type: string

Target library filename (e.g., "kernel32.dll").

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_functions

Type: uint64

Total count of functions imported from this library.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### functions

Type: array of pe.Function

Individual functions imported from the library.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.Function

### name

Type: string

Name of the imported function.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### ordinal

Type: uint32

Ordinal index of the function.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### rva

Type: uint32

Relative virtual address (RVA) or offset pointing to the function import thunk.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.Export

### name

Type: string

Name of the exported function.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### ordinal

Type: uint32

Ordinal index of the exported function.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### rva

Type: uint32

Relative virtual address (RVA) pointing to the exported function.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### offset

Type: uint32

Physical file offset of the exported function.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### forward_name

Type: string

Forwarder string, if the export resolves to a function in another library.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.Signature

### subject

Type: string

Subject name specified in the certificate.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### issuer

Type: string

Issuer name specified in the certificate.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### thumbprint

Type: string

Unique thumbprint value of the certificate.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### version

Type: int64

Internal version format of the digital signature.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### algorithm

Type: string

Public key algorithm identifier string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### algorithm_oid

Type: string

OID value representing the public key algorithm.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### serial

Type: string

Serial number of the certificate.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### not_before

Type: int64

Unix timestamp representing the start of the validity window.

Field annotations:
```json
{
  "fmt": "t"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### not_after

Type: int64

Unix timestamp representing the end of the validity window.

Field annotations:
```json
{
  "fmt": "t"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### verified

Type: bool

True if the cryptographic verification of the signature succeeded.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### digest_alg

Type: string

Digest algorithm utilized in the signature process.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### digest

Type: string

Content digest generated by the signer.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### file_digest

Type: string

Digest computed directly from the binary payload.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_certificates

Type: uint64

Number of certificates embedded in the signature chain.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### number_of_countersignatures

Type: uint64

Number of countersignatures associated with this signature.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### signer_info

Type: pe.SignerInfo

Details regarding the primary signer entity.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### certificates

Type: array of pe.Certificate

Certificates making up the signing chain.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### countersignatures

Type: array of pe.CounterSignature

Countersignatures validating the time and source of the primary signature.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.SignerInfo

### program_name

Type: string

Program description extracted from the SpcSpOpusInfo block.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### more_info

Type: string

URL containing supplemental details about the software.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### digest

Type: string

Hash digest calculated by the primary signer.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### digest_alg

Type: string

Algorithm used to generate the signer digest.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### chain

Type: array of pe.Certificate

Certificate chain validating the signer.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.Certificate

### issuer

Type: string

Issuer of this individual certificate.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### subject

Type: string

Intended subject of this certificate.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### thumbprint

Type: string

Thumbprint identifying the certificate.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### version

Type: int64

Internal format version of the certificate.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### algorithm

Type: string

Public key cryptographic algorithm string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### algorithm_oid

Type: string

Public key cryptographic algorithm OID.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### serial

Type: string

Unique serial number of the certificate.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### not_before

Type: int64

Start date of the certificate validity period.

Field annotations:
```json
{
  "fmt": "t"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### not_after

Type: int64

End date of the certificate validity period.

Field annotations:
```json
{
  "fmt": "t"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.CounterSignature

### verified

Type: bool

True if the countersignature successfully verified.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### sign_time

Type: int64

Unix timestamp indicating when the signature was countersigned.

Field annotations:
```json
{
  "fmt": "t"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### digest

Type: string

Hash digest of the countersignature payload.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### digest_alg

Type: string

Algorithm used to compute the countersignature digest.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### chain

Type: array of pe.Certificate

Certificate chain associated with the countersigning entity.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.Overlay

### offset

Type: uint64

File offset marking the start of the appended overlay content.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

### size

Type: uint64

Total size in bytes of the overlay data.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/pe.proto

## pe.is_32bit()

Return type: Option<bool>

Returns true if the file is a 32-bit PE.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L52

## pe.is_64bit()

Return type: Option<bool>

Returns true if the file is a 64-bit PE.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L59

## pe.is_dll()

Return type: Option<bool>

Returns true if the file is dynamic link library (DLL)

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L66

## pe.rva_to_offset(rva: i64)

Return type: Option<i64>

Convert a relative virtual address (RVA) to a file offset.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L73

## pe.calculate_checksum()

Return type: Option<i64>

Returns the PE checksum, as calculated by YARA.

This is useful for comparing with the checksum appearing in the PE header
(pe.checksum) in order to verify if the actual checksum matches the one
in the header.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L90

## pe.section_index(name: RuntimeString)

Return type: Option<i64>

Returns the index in the section table of the first section with the given
name.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L174

## pe.section_index(offset: i64)

Return type: Option<i64>

Returns the index in the section table of the first section that contains
the given file offset.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L189

## pe.imphash()

Return type: Option<Lowercase<FixedLenString<32>>>

Returns the PE import hash.

The import hash represents the MD5 checksum of the PE's import table
following a normalization process. PE files sharing the same import hash
import precisely identical functions from the same DLLs. This characteristic
often signifies file similarity, despite not being byte-for-byte identical.
For additional details, refer to:
https://www.mandiant.com/resources/blog/tracking-malware-import-hashing

The resulting hash string is consistently in lowercase.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L217

## pe.rich_signature.toolid(toolid: i64)

Return type: Option<i64>

Returns the number of toolid records with the given toolid.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L300

## pe.rich_signature.toolid(toolid: i64, version: i64)

Return type: Option<i64>

Returns the number of toolid records matching the given toolid and version.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L322

## pe.rich_signature.version(version: i64)

Return type: Option<i64>

Returns the number of toolid records matching the given version.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L306

## pe.rich_signature.version(version: i64, toolid: i64)

Return type: Option<i64>

Returns the number of toolid records matching the given toolid and version.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L312

## pe.imports(dll_name: RuntimeString)

Return type: Option<i64>

Returns the number of functions imported by the PE from `dll_name`.

`dll_name` is case-insensitive.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L365

## pe.imports(dll_name: RuntimeString, func_name: RuntimeString)

Return type: Option<bool>

Returns true if the PE imports `func_name` from `dll_name`.

Both `func_name` and `dll_name` are case-insensitive.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L381

## pe.imports(dll_name: RuntimeString, ordinal: i64)

Return type: Option<i64>

Returns true if the PE imports `ordinal` from `dll_name`.

`dll_name` is case-insensitive.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L400

## pe.imports(dll_name: RegexId, func_name: RegexId)

Return type: Option<i64>

Returns the number of imported functions where the function's name matches
`func_name` and the DLL name matches `dll_name`.

Both `dll_name` and `func_name` are case-sensitive unless you use the "/i"
modifier in the regexp, as shown in the example below.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L419

## pe.imports(import_flags: i64, dll_name: RuntimeString)

Return type: Option<i64>

Returns the number of functions imported by the PE from `dll_name`.

`dll_name` is case-insensitive. `import_flags` specify the types of
import which should be taken into account. This value can be composed
by a bitwise OR of the following values:

* `pe.IMPORT_STANDARD` : standard import only
* `pe.IMPORT_DELAYED` : delayed imports only
* `pe.IMPORT_ANY` : both standard and delayed imports

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L442

## pe.imports(import_flags: i64, dll_name: RuntimeString, func_name: RuntimeString)

Return type: Option<bool>

Returns true if the PE imports `func_name` from `dll_name`.

Both `func_name` and `dll_name` are case-insensitive. See [`imports_dll`]
for details about the `import_flags` argument.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L460

## pe.imports(import_flags: i64, dll_name: RuntimeString, ordinal: i64)

Return type: Option<bool>

Returns true if the PE imports `ordinal` from `dll_name`.

`dll_name` is case-insensitive. See [`imports_dll`] for details about
the `import_flags` argument.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L481

## pe.imports(import_flags: i64, dll_name: RegexId, func_name: RegexId)

Return type: Option<i64>

Returns the number of imported functions where the function's name matches
`func_name` and the DLL name matches `dll_name`.

Both `dll_name` and `func_name` are case-sensitive unless you use the "/i"
modifier in the regexp, as shown in the example below. See [`imports_dll`]
for details about the `import_flags` argument.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L504

## pe.import_rva(dll_name: RuntimeString, func_name: RuntimeString)

Return type: Option<i64>

Returns the RVA of an import where the DLL name matches
`dll_name` and the function name matches `func_name`.

Both `dll_name` and `func_name` are case-insensitive.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L523

## pe.import_rva(dll_name: RuntimeString, ordinal: i64)

Return type: Option<i64>

Returns the RVA of an import where the DLL name matches
`dll_name` and the ordinal number is `ordinal`.

`dll_name` is case-insensitive.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L541

## pe.delayed_import_rva(dll_name: RuntimeString, func_name: RuntimeString)

Return type: Option<i64>

Returns the RVA of a delayed import where the DLL name matches
`dll_name` and the function name matches `func_name`.

Both `dll_name` and `func_name` are case-insensitive.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L559

## pe.delayed_import_rva(dll_name: RuntimeString, ordinal: i64)

Return type: Option<i64>

Returns the RVA of an import where the DLL name matches
`dll_name` and the ordinal number is `ordinal`.

`dll_name` is case-insensitive.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L577

## pe.exports(func_name: RuntimeString)

Return type: Option<bool>

Returns true if the PE file exports a function with the given name.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L592

## pe.exports(ordinal: i64)

Return type: Option<bool>

Returns true if the PE file exports a function with the given ordinal.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L600

## pe.exports(func_name: RegexId)

Return type: Option<bool>

Returns true if the PE file exports a function with a name that matches
the given regular expression.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L608

## pe.exports_index(func_name: RuntimeString)

Return type: Option<i64>

Returns true if the PE file exports a function with the given name.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L615

## pe.exports_index(ordinal: i64)

Return type: Option<i64>

Returns true if the PE file exports a function with the given ordinal.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L627

## pe.exports_index(func_name: RegexId)

Return type: Option<i64>

Returns true if the PE file exports a function with a name that matches
the given regular expression.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L637

## pe.locale(loc: i64)

Return type: Option<bool>

Returns true if the PE contains some resource with the specified locale
identifier.

Locale identifiers are 16-bit integers and can be found here:
https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/available-language-packs-for-windows?view=windows-11

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L650

## pe.language(lang: i64)

Return type: Option<bool>

Returns true if the PE contains some resource with the specified language
identifier.

Language identifiers are the lowest 8-bit of locale identifiers and can
be found here:
https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/available-language-packs-for-windows?view=windows-11

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L668

## pe.Signature.valid_on(timestamp: i64)

Return type: Option<bool>

Returns true if the signature was valid on the date indicated by `timestamp`.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/pe/mod.rs#L681
