# macho — YARA-X 1.20.0

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

Generated from the official protobuf definitions and Rust exports. Availability depends on the engine build and field feature restrictions.

## macho.Macho

### magic

Type: uint32

Magic identifier indicating the file architecture.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### cputype

Type: uint32

Target architecture designation.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### cpusubtype

Type: uint32

Specific sub-architecture variant.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### filetype

Type: uint32

Categorization of the Mach-O executable.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### ncmds

Type: uint32

Number of load commands defined inside the binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### sizeofcmds

Type: uint32

Combined byte size of all load commands.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### flags

Type: uint32

Global bitwise flags characterizing the binary.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### reserved

Type: uint32

Reserved padding element.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### number_of_segments

Type: uint64

Number of segments parsed.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `macho.segments.len()` instead",
    "replacement": "segments.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### dynamic_linker

Type: bytes

Standard dynamic linker specification path.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### entry_point

Type: uint64

Execution entry point address.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### stack_size

Type: uint64

Stack size allocation requested.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### source_version

Type: string

Build source version metadata string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### symtab

Type: macho.Symtab

Standard symbol table block.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### dysymtab

Type: macho.Dysymtab

Detailed dynamic symbol table block.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### code_signature_data

Type: macho.LinkedItData

Code signature data payload block.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### segments

Type: array of macho.Segment

Top-level segments parsed from the binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### dylibs

Type: array of macho.Dylib

Linked external libraries.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### dyld_info

Type: macho.DyldInfo

Dynamic loader metadata information block.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### rpaths

Type: array of bytes

Executable run path definition strings.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### entitlements

Type: array of string

Defined app entitlement descriptor strings.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### certificates

Type: array of macho.Certificate

Cryptographic certificates validating the signature.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### uuid

Type: string

Binary UUID descriptor string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### build_version

Type: macho.BuildVersion

General build version metadata block.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### min_version

Type: macho.MinVersion

Minimum OS version requirements.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### exports

Type: array of string

Standard exported symbol strings.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### imports

Type: array of string

Standard imported symbol strings.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### linker_options

Type: array of bytes

Custom options passed directly to the linker.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### fat_magic

Type: uint32

Magic constant identifying the file as a Fat binary.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### nfat_arch

Type: uint32

Total count of different architectures embedded in the Fat binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### fat_arch

Type: array of macho.FatArch

Individual descriptors for each embedded architecture.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### file

Type: array of macho.File

Independent Mach-O binaries extracted from the universal Fat payload.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ARM_V5TEJ

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ARM64_ALL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ARM_ALL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ARM_V4T

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ARM_V6

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ARM_V5

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ARM_XSCALE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ARM_V7

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ARM_V7F

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ARM_V7S

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ARM_V7K

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ARM_V6M

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ARM_V7M

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ARM_V7EM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_I386_ALL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_TYPE_I386

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_PENT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_PENTPRO

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_PENTII_M3

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_PENTII_M5

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_PENTIUM_3

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_PENTIUM_3_M

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_PENTIUM_3_XEON

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_PENTIUM_M

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_PENTIUM_4

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_PENTIUM_4_M

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_INTEL_MODEL_ALL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_386

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_486

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_486SX

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_586

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_CELERON

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_CELERON_MOBILE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ITANIUM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_ITANIUM_2

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_XEON

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_XEON_MP

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_MC980000_ALL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_MC98601

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_POWERPC_ALL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_POWERPC_601

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_POWERPC_602

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_POWERPC_603

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_POWERPC_603e

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_POWERPC_603ev

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_POWERPC_604

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_POWERPC_604e

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_POWERPC_620

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_POWERPC_750

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_POWERPC_7400

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_POWERPC_7450

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_POWERPC_970

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_SPARC_ALL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_TYPE_MC680X0

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_TYPE_X86

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_TYPE_X86_64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_TYPE_MIPS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_TYPE_MC98000

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_TYPE_ARM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_TYPE_ARM64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_TYPE_MC88000

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_TYPE_SPARC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_TYPE_POWERPC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_TYPE_POWERPC64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_X86_64_ALL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MACOSX

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### IPHONEOS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### TVOS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### WATCHOS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### FAT_MAGIC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### FAT_CIGAM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### FAT_MAGIC_64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### FAT_CIGAM_64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_NOUNDEFS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_INCRLINK

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_DYLDLINK

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_BINDATLOAD

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_PREBOUND

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_SPLIT_SEGS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_LAZY_INIT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_TWOLEVEL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_FORCE_FLAT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_NOMULTIDEFS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_NOFIXPREBINDING

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_PREBINDABLE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_ALLMODSBOUND

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_SUBSECTIONS_VIA_SYMBOLS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_CANONICAL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_WEAK_DEFINES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_BINDS_TO_WEAK

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_ALLOW_STACK_EXECUTION

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_ROOT_SAFE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_SETUID_SAFE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_NO_REEXPORTED_DYLIBS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_PIE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_DEAD_STRIPPABLE_DYLIB

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_HAS_TLV_DESCRIPTORS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_NO_HEAP_EXECUTION

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_APP_EXTENSION_SAFE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_OBJECT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_EXECUTE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_FVMLIB

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_CORE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_PRELOAD

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_DYLIB

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_DYLINKER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_BUNDLE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_DYLIB_STUB

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_DSYM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_KEXT_BUNDLE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_MAGIC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_CIGAM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_MAGIC_64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### MH_CIGAM_64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_ARCH_ABI64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### CPU_SUBTYPE_LIB64

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_ATTR_PURE_INSTRUCTIONS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_ATTR_NO_TOC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_ATTR_STRIP_STATIC_SYMS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_ATTR_NO_DEAD_STRIP

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_ATTR_LIVE_SUPPORT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_ATTR_SELF_MODIFYING_CODE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_ATTR_DEBUG

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_ATTR_SOME_INSTRUCTIONS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_ATTR_EXT_RELOC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_ATTR_LOC_RELOC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### SECTION_TYPE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### SECTION_ATTRIBUTES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_REGULAR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_ZEROFILL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_CSTRING_LITERALS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_4BYTE_LITERALS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_8BYTE_LITERALS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_LITERAL_POINTERS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_NON_LAZY_SYMBOL_POINTERS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_LAZY_SYMBOL_POINTERS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_SYMBOL_STUBS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_MOD_INIT_FUNC_POINTERS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_MOD_TERM_FUNC_POINTERS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_COALESCED

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_GB_ZEROFILL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_INTERPOSING

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_16BYTE_LITERALS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_DTRACE_DOF

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_LAZY_DYLIB_SYMBOL_POINTERS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_THREAD_LOCAL_REGULAR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_THREAD_LOCAL_ZEROFILL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_THREAD_LOCAL_VARIABLES

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_THREAD_LOCAL_VARIABLE_POINTERS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### S_THREAD_LOCAL_INIT_FUNCTION_POINTERS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### SG_HIGHVM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### SG_FVMLIB

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### SG_NORELOC

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### SG_PROTECTED_VERSION_1

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.Symtab

### symoff

Type: uint32

Physical offset to the start of the symbol table.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### nsyms

Type: uint32

Count of total symbols stored.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### stroff

Type: uint32

Physical offset to the string table data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### strsize

Type: uint32

Size in bytes of the string table.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### entries

Type: array of bytes

Individual entries stored in the table.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### nlists

Type: array of macho.Nlist

Descriptive nlist entries for symbols.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.Nlist

### n_strx

Type: uint32

Index into the string table representing the symbol name.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### n_type

Type: uint32

Symbol type flag designation.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### n_sect

Type: uint32

Section index associated with the symbol.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### n_desc

Type: uint32

Description attributes of the symbol.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### n_value

Type: uint64

Value or address of the symbol.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.Dysymtab

### ilocalsym

Type: uint32

Index of the first local symbol.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### nlocalsym

Type: uint32

Total number of local symbols.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### iextdefsym

Type: uint32

Index of the first externally defined symbol.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### nextdefsym

Type: uint32

Total count of externally defined symbols.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### iundefsym

Type: uint32

Index of the first undefined symbol.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### nundefsym

Type: uint32

Total count of undefined symbols.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### tocoff

Type: uint32

Physical file offset to the table of contents.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### ntoc

Type: uint32

Total entries within the table of contents.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### modtaboff

Type: uint32

Physical offset to the module table.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### nmodtab

Type: uint32

Total module entries in the module table.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### extrefsymoff

Type: uint32

File offset to external reference symbol entries.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### nextrefsyms

Type: uint32

Total entries for external reference symbols.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### indirectsymoff

Type: uint32

File offset to indirect symbol entries.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### nindirectsyms

Type: uint32

Count of indirect symbol elements.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### extreloff

Type: uint32

File offset to external relocation entries.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### nextrel

Type: uint32

Count of external relocation records.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### locreloff

Type: uint32

File offset to local relocation elements.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### nlocrel

Type: uint32

Total count of local relocation entries.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.LinkedItData

### dataoff

Type: uint32

File offset pointing to the linked data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### datasize

Type: uint32

Size in bytes of the linked data payload.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.Segment

### segname

Type: bytes

Text identifier of the segment.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### vmaddr

Type: uint64

Virtual memory address where the segment is mapped.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### vmsize

Type: uint64

Total size of the mapped segment in virtual memory.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### fileoff

Type: uint64

File offset pointing to the segment contents on disk.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### filesize

Type: uint64

Total physical length of the segment inside the file.

Reserved identifier in the YARA-X 1.20.0 parser

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### maxprot

Type: uint32

Maximum virtual memory protection state applicable.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### initprot

Type: uint32

Initial virtual memory protection applied at load time.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### nsects

Type: uint32

Number of sections contained inside the segment.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### flags

Type: uint32

Bitwise flags controlling segment properties.

Field annotations:
```json
{
  "fmt": "flags:SegmentFlag"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### sections

Type: array of macho.Section

Array of sections nested within the segment.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.Section

### segname

Type: bytes

Segment name the section belongs to.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### sectname

Type: bytes

Individual section designation string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### addr

Type: uint64

Address where the section is mapped in virtual memory.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### size

Type: uint64

Total virtual memory size occupied by the section.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### offset

Type: uint32

File offset pointing to the section data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### align

Type: uint32

Memory alignment constraint of the section.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### reloff

Type: uint32

File offset to relocation entries.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### nreloc

Type: uint32

Total count of relocation entries.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### flags

Type: uint32

Bitwise flags and attributes characterizing the section.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### reserved1

Type: uint32

First reserved padding field.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### reserved2

Type: uint32

Second reserved padding field.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### reserved3

Type: uint32

Third reserved padding field.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.Dylib

### name

Type: bytes

Library name string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### timestamp

Type: uint32

Build timestamp of the dynamic library.

Field annotations:
```json
{
  "fmt": "t"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### compatibility_version

Type: string

Compatibility version requirement string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### current_version

Type: string

Current version designation string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.DyldInfo

### rebase_off

Type: uint32

File offset to the rebase information.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### rebase_size

Type: uint32

Size in bytes of the rebase payload.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### bind_off

Type: uint32

File offset to the primary binding info.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### bind_size

Type: uint32

Size of the binding data in bytes.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### weak_bind_off

Type: uint32

File offset to weak binding definitions.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### weak_bind_size

Type: uint32

Size of weak binding definitions.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### lazy_bind_off

Type: uint32

File offset to lazy binding definitions.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### lazy_bind_size

Type: uint32

Size of lazy binding definitions.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### export_off

Type: uint32

File offset to exported symbols and data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### export_size

Type: uint32

Size of the export payload.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.Certificate

### issuer

Type: string

Name of the issuer of the certificate.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### subject

Type: string

Subject designation of the certificate.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### is_self_signed

Type: bool

True if the certificate is self-signed.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.BuildVersion

### platform

Type: uint32

Target platform designation.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### minos

Type: string

Minimum OS version required as a string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### sdk

Type: string

Version string of the SDK utilized.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### ntools

Type: uint32

Number of build tools embedded.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### tools

Type: array of macho.BuildTool

Information regarding individual tools utilized in the build.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.BuildTool

### tool

Type: uint32

Identifier representing the tool utilized.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### version

Type: string

Version string corresponding to the tool.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.MinVersion

### device

Type: macho.DeviceType

Target device type (e.g., MACOSX, IPHONEOS).

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### version

Type: string

Minimum OS version string required to run the binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### sdk

Type: string

Version string of the SDK used to build the binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.DeviceType

### MACOSX

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### IPHONEOS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### TVOS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### WATCHOS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.FatArch

### cputype

Type: uint32

Target architecture designation of the embedded binary.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### cpusubtype

Type: uint32

Sub-architecture designation.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### offset

Type: uint64

File offset referencing the start of the embedded binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### size

Type: uint64

Size in bytes of the embedded binary payload.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### align

Type: uint32

Required byte alignment of the binary payload.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### reserved

Type: uint32

Reserved internal field.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.File

### magic

Type: uint32

Magic identifier indicating the file architecture.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### cputype

Type: uint32

Primary architecture designation of the embedded binary.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### cpusubtype

Type: uint32

Specific sub-architecture variant.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### filetype

Type: uint32

Binary file type categorization.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### ncmds

Type: uint32

Total count of load commands embedded inside the header.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### sizeofcmds

Type: uint32

Combined byte size of all load commands.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### flags

Type: uint32

Bitwise flags characterizing the binary.

Field annotations:
```json
{
  "fmt": "flags:FileFlag"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### reserved

Type: uint32

Internal reserved field.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### number_of_segments

Type: uint64

Number of segments parsed from the binary.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `segments.len()` instead",
    "replacement": "segments.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### dynamic_linker

Type: bytes

Standard path of the dynamic linker.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### entry_point

Type: uint64

Execution entry point offset or address.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### stack_size

Type: uint64

Size of the stack allocated by the loader.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### source_version

Type: string

Source version metadata string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### segments

Type: array of macho.Segment

Segments nested inside the binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### dylibs

Type: array of macho.Dylib

External dynamic libraries referenced.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### rpaths

Type: array of bytes

Standard run paths utilized to locate libraries.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### entitlements

Type: array of string

App entitlement strings defined within the binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### symtab

Type: macho.Symtab

Basic symbol table definitions.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### dysymtab

Type: macho.Dysymtab

Detailed dynamic symbol table definitions.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### dyld_info

Type: macho.DyldInfo

Dynamic linker information payload.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### code_signature_data

Type: macho.LinkedItData

Linked code signature data representation.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### certificates

Type: array of macho.Certificate

Certificates verifying the code signature.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### uuid

Type: string

Standard UUID assigned to the binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### build_version

Type: macho.BuildVersion

Standard build version metadata.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### min_version

Type: macho.MinVersion

Minimum OS requirement specifications.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### exports

Type: array of string

Exported symbol descriptors.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### imports

Type: array of string

Imported symbol descriptors.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

### linker_options

Type: array of bytes

Linker options passed during binary assembly.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/macho.proto

## macho.file_index_for_arch(type_arg: i64)

Return type: Option<i64>

Get the index of a Mach-O file within a fat binary based on CPU type.

This function iterates through the architecture types contained in a
Mach-O fat binary and returns the index of the file that matches the
specified CPU type.

# Arguments

* `ctx`: A mutable reference to the scanning context.
* `type_arg`: The CPU type to search for within the fat binary.

# Returns

An `Option<i64>` containing the index of the matching Mach-O file, or
`None` if no match is found.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/macho/mod.rs#L50

## macho.file_index_for_arch(type_arg: i64, subtype_arg: i64)

Return type: Option<i64>

Get the index of a Mach-O file within a fat binary based on both
CPU type and subtype.

This function extends `file_index_type` by also considering the CPU subtype
during the search, allowing for more precise matching.

# Arguments

* `ctx`: A mutable reference to the scanning context.
* `type_arg`: The CPU type to search for.
* `subtype_arg`: The CPU subtype to search for.

# Returns

An `Option<i64>` containing the index of the matching Mach-O file, or
`None` if no match is found.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/macho/mod.rs#L86

## macho.entry_point_for_arch(type_arg: i64)

Return type: Option<i64>

Get the real entry point offset for a specific CPU type within a fat
Mach-O binary.

It navigates through the architectures in the binary, finds the one that
matches the specified CPU type, and returns its entry point offset.

# Arguments

* `ctx`: A mutable reference to the scanning context.
* `type_arg`: The CPU type of the desired architecture.

# Returns

An `Option<i64>` containing the offset of the entry point for the specified
architecture, or `None` if not found.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/macho/mod.rs#L127

## macho.entry_point_for_arch(type_arg: i64, subtype_arg: i64)

Return type: Option<i64>

Get the real entry point offset for a specific CPU type and subtype
within a fat Mach-O binary.

Similar to `ep_for_arch_type`, but adds consideration for the CPU subtype
to allow for more precise location of the entry point.

# Arguments

* `ctx`: A mutable reference to the scanning context.
* `type_arg`: The CPU type of the desired architecture.
* `subtype_arg`: The CPU subtype of the desired architecture.

# Returns

An `Option<i64>` containing the offset of the entry point for the specified
architecture and subtype, or `None` if not found.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/macho/mod.rs#L165

## macho.has_entitlement(entitlement: RuntimeString)

Return type: Option<bool>

Returns true if the Mach-O parsed entitlements contain `entitlement`

`entitlement` is case-insensitive.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/macho/mod.rs#L196

## macho.has_dylib(dylib_name: RuntimeString)

Return type: Option<bool>

Returns true if the Mach-O parsed dylibs contain `dylib_name`

`dylib_name` is case-insensitive.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/macho/mod.rs#L224

## macho.has_rpath(rpath: RuntimeString)

Return type: Option<bool>

Returns true if the Mach-O parsed rpaths contain `rpath`

`rpath` is case-insensitive.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/macho/mod.rs#L253

## macho.has_import(import: RuntimeString)

Return type: Option<bool>

Returns true if the Mach-O parsed imports contain `import`

`import` is case-insensitive

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/macho/mod.rs#L278

## macho.has_export(export: RuntimeString)

Return type: Option<bool>

Returns true if the Mach-O parsed exports contain `export`

`export` is case-insensitive

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/macho/mod.rs#L303

## macho.dylib_hash()

Return type: Option<Lowercase<FixedLenString<32>>>

Returns a md5 hash of the dylibs designated in the mach-o binary

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/macho/mod.rs#L326

## macho.entitlement_hash()

Return type: Option<Lowercase<FixedLenString<32>>>

Returns a md5 hash of the entitlements designated in the mach-o binary

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/macho/mod.rs#L380

## macho.export_hash()

Return type: Option<Lowercase<FixedLenString<32>>>

Returns a md5 hash of the export symbols in the mach-o binary

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/macho/mod.rs#L431

## macho.import_hash()

Return type: Option<Lowercase<FixedLenString<32>>>

Returns a md5 hash of the imported symbols in the mach-o binary

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/macho/mod.rs#L482

## macho.symhash()

Return type: Option<Lowercase<FixedLenString<32>>>

Returns a md5 hash of specific parts of the symbol table
as defined by http://github.com/threatstream/symhash

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/macho/mod.rs#L534
