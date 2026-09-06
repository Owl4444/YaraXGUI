# dotnet — YARA-X 1.20.0

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

Generated from the official protobuf definitions and Rust exports. Availability depends on the engine build and field feature restrictions.

## dotnet.Dotnet

### is_dotnet

Type: bool

True if the file is a valid .NET framework executable.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### module_name

Type: string

Module name designation extracted from the assembly.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### version

Type: string

Version string of the embedded module.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### number_of_streams

Type: uint64

Total count of embedded streams inside the file.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `dotnet.streams.len()` instead",
    "replacement": "streams.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### number_of_guids

Type: uint64

Count of unique GUIDs defined within the module.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `dotnet.guids.len()` instead",
    "replacement": "guids.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### number_of_resources

Type: uint64

Total number of individual resources embedded.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `dotnet.resources.len()` instead",
    "replacement": "resources.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### number_of_generic_parameters

Type: uint64

Count of generic parameters defined inside the assembly.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### number_of_classes

Type: uint64

Total count of classes extracted from the executable.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `dotnet.classes.len()` instead",
    "replacement": "classes.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### number_of_assembly_refs

Type: uint64

Number of external assembly references declared.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `dotnet.assembly_refs.len()` instead",
    "replacement": "assembly_refs.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### number_of_modulerefs

Type: uint64

Number of external module references defined.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `dotnet.modulerefs.len()` instead",
    "replacement": "modulerefs.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### number_of_user_strings

Type: uint64

Count of strings defined inside the user string heap.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `dotnet.user_strings.len()` instead",
    "replacement": "user_strings.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### number_of_constants

Type: uint64

Number of constant elements stored inside the assembly.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `dotnet.constants.len()` instead",
    "replacement": "constants.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### number_of_field_offsets

Type: uint64

Total count of structured field offsets available.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `dotnet.field_offsets.len()` instead",
    "replacement": "field_offsets.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### typelib

Type: string

Core type library representation identifier string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### streams

Type: array of dotnet.Stream

Individual streams mapped from the metadata root.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### guids

Type: array of string

Distinct GUID values associated with the executable.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### constants

Type: array of bytes

Internal constants extracted from the binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### assembly

Type: dotnet.Assembly

Structured metadata describing the primary assembly.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### assembly_refs

Type: array of dotnet.AssemblyRef

External assembly elements referenced by the program.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### resources

Type: array of dotnet.Resource

Specific resources stored directly inside the module.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### classes

Type: array of dotnet.Class

Defined classes and types structured from the program.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### field_offsets

Type: array of uint32

Relative offsets describing specific fields.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### user_strings

Type: array of bytes

String definitions extracted from the user string pool.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### modulerefs

Type: array of string

Descriptive names of external modules imported.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

## dotnet.Stream

### name

Type: string

Descriptive name of the metadata stream.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### offset

Type: uint32

Address or file offset marking the beginning of the stream.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### size

Type: uint32

Exact size of the stream inside the binary.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

## dotnet.Assembly

### name

Type: string

Name of the active assembly.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### culture

Type: string

Standard culture setting applicable to the assembly.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### version

Type: dotnet.Version

Version descriptor assigned to the assembly.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

## dotnet.Version

### major

Type: uint32

Major format specification number.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### minor

Type: uint32

Minor format specification number.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### build_number

Type: uint32

Designated build assignment number.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### revision_number

Type: uint32

Internal code revision tracking number.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

## dotnet.AssemblyRef

### name

Type: string

Identifier string representing the external assembly.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### public_key_or_token

Type: bytes

Cryptographic key or access token assigned to the assembly.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### version

Type: dotnet.Version

Standard version requirement for the referenced assembly.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

## dotnet.Resource

### offset

Type: uint32

File offset marking the start of the resource data.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### length

Type: uint32

Physical length of the resource inside the binary.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### name

Type: string

Descriptive name string of the stored resource.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

## dotnet.Class

### fullname

Type: string

Full namespace and class name descriptor.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### name

Type: string

Individual class designation name string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### namespace

Type: string

Target namespace string containing the class.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### visibility

Type: string

Access visibility modifier applied to the class.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### type

Type: string

Categorization of the class type.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### abstract

Type: bool

True if the class is marked as abstract.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### sealed

Type: bool

True if the class is marked as sealed.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### number_of_base_types

Type: uint64

Count of inherited base types declared by the class.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `base_types.len()` instead",
    "replacement": "base_types.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### number_of_generic_parameters

Type: uint64

Total count of generic parameters specified.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `generic_parameters.len()` instead",
    "replacement": "generic_parameters.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### number_of_methods

Type: uint64

Number of methods explicitly defined inside the class.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `methods.len()` instead",
    "replacement": "methods.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### base_types

Type: array of string

Distinct base types inherited by this class.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### generic_parameters

Type: array of string

Defined generic parameters applicable to the class.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### methods

Type: array of dotnet.Method

Methods and subroutines implemented within the class.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

## dotnet.Method

### name

Type: string

Individual function name string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### visibility

Type: string

Access visibility scope applied to the method.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### abstract

Type: bool

True if the function is an abstract definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### static

Type: bool

True if the function is marked as static.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### virtual

Type: bool

True if the function acts as a virtual method.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### final

Type: bool

True if the function is restricted as final.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### return_type

Type: string

Standard return type specification string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### number_of_generic_parameters

Type: uint64

Count of generic parameters explicitly defined for the method.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `generic_parameters.len()` instead",
    "replacement": "generic_parameters.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### number_of_parameters

Type: uint64

Number of individual parameters passed to the method.

Field annotations:
```json
{
  "deprecation_notice": {
    "text": "this field is deprecated",
    "help": "use `parameters.len()` instead",
    "replacement": "parameters.len()"
  }
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### generic_parameters

Type: array of string

Distinct generic parameters linked to the method.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### parameters

Type: array of dotnet.Param

Detailed argument definitions accepted by the function.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

## dotnet.Param

### name

Type: string

Target parameter identifier name string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto

### type

Type: string

Designated parameter type string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dotnet.proto
