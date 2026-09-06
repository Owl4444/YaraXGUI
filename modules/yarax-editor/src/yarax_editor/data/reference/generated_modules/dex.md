# dex — YARA-X 1.20.0

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

Generated from the official protobuf definitions and Rust exports. Availability depends on the engine build and field feature restrictions.

## dex.Dex

### is_dex

Type: bool

True if the file is a valid Dalvik Executable (DEX).

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### header

Type: dex.DexHeader

Standard header items parsed from the binary.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### strings

Type: array of string

Array of strings extracted from the string pool.

Reserved identifier in the YARA-X 1.20.0 parser

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### types

Type: array of string

Data types explicitly defined in the type pool.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### protos

Type: array of dex.ProtoItem

Function prototypes structured from the prototype pool.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### fields

Type: array of dex.FieldItem

Distinct class fields extracted from the field list.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### methods

Type: array of dex.MethodItem

Specific subroutines and methods defined.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### class_defs

Type: array of dex.ClassItem

Structured class definition objects.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### map_list

Type: dex.MapList

Mapping metadata table listing item offsets and sizes.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_PUBLIC

Type: integer

public: visible everywhere (class, field, method)

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_PRIVATE

Type: integer

private: only visible to defining class (class, field, method)

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_PROTECTED

Type: integer

protected: visible to package and subclasses (class, field, method)

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_STATIC

Type: integer

static:
   - class: not constructed with an outer this reference
   - field: global to defining class
   - method: does not take a this argument

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_FINAL

Type: integer

final:
   - class: not subclassable
   - field: immutable after construction
   - method: not overridable

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_SYNCHRONIZED

Type: integer

synchronized: method has associated lock automatically acquired around call.
 Note: only valid if ACC_NATIVE is also set.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_BRIDGE

Type: integer

bridge: compiler-generated method to provide type-safe bridge

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_VARARGS

Type: integer

varargs: last argument should be treated as a "rest" argument by compiler

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_NATIVE

Type: integer

native: implemented in native code

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_INTERFACE

Type: integer

interface: multiply-implementable abstract class

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_ABSTRACT

Type: integer

abstract:
   - class: not directly instantiable
   - method: unimplemented by this class

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_STRICT

Type: integer

strictfp: strict rules for floating-point arithmetic

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_SYNTHETIC

Type: integer

synthetic: not directly defined in source code (class, field, method)

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_ANNOTATION

Type: integer

annotation: declared as an annotation class

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_ENUM

Type: integer

enum:
   - class: declared as an enumerated type
   - field: declared as an enumerated value

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_CONSTRUCTOR

Type: integer

constructor: constructor method (class or instance initializer)

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_DECLARED_SYNCHRONIZED

Type: integer

declared synchronized: declared with 'synchronized' keyword

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_VOLATILE

Type: integer

volatile (field): special access rules to help with thread safety

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### ACC_TRANSIENT

Type: integer

transient (field): not to be saved by default serialization

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_HEADER_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_STRING_ID_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_TYPE_ID_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_PROTO_ID_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_FIELD_ID_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_METHOD_ID_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_CLASS_DEF_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_CALL_SITE_ID_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_METHOD_HANDLE_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_MAP_LIST

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_TYPE_LIST

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_ANNOTATION_SET_REF_LIST

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_ANNOTATION_SET_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_CLASS_DATA_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_CODE_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_STRING_DATA_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_DEBUG_INFO_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_ANNOTATION_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_ENCODED_ARRAY_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_ANNOTATIONS_DIRECTORY_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_HIDDENAPI_CLASS_DATA_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

## dex.DexHeader

### magic

Type: uint32

Magic identifier characterizing the file type.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### version

Type: uint32

Format version designation (e.g., 35, 36, 37).

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### checksum

Type: uint32

Standard Adler32 checksum of the remainder of the file.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### signature

Type: string

Cryptographic SHA-1 signature of the remaining file contents.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### file_size

Type: uint32

Physical size in bytes of the complete file.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### header_size

Type: uint32

Combined size in bytes of the binary header block.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### endian_tag

Type: uint32

Byte ordering identifier constant.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### link_size

Type: uint32

Physical size of the link section.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### link_off

Type: uint32

Offset pointing to the link section data.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### data_size

Type: uint32

Size in bytes of the main data section.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### data_off

Type: uint32

File offset pointing to the main data block.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### container_size

Type: uint32

Combined size constraint allocated for the container.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### header_offset

Type: uint32

File offset marking the beginning of the primary header.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

## dex.ProtoItem

### shorty

Type: string

Short-form signature representing the return and argument types.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### return_type

Type: string

Standard data type descriptor of the return value.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### parameters_count

Type: uint32

Total count of arguments accepted by the prototype.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### parameters

Type: array of string

Data type descriptions corresponding to each argument.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

## dex.FieldItem

### class

Type: string

Name of the parent class defining the field.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### type

Type: string

Specific data type categorization of the field.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### name

Type: string

Descriptive string identifier assigned to the field.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

## dex.MethodItem

### class

Type: string

Parent class descriptor string containing the method.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### proto

Type: dex.ProtoItem

Signature prototype defining the function arguments and return value.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### name

Type: string

Individual function name assigned to the method.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

## dex.ClassItem

### class

Type: string

Core descriptor representing the class type.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### access_flags

Type: uint32

Bitwise flags specifying accessibility constraints and attributes.

Field annotations:
```json
{
  "fmt": "flags:AccessFlag"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### superclass

Type: string

Superclass descriptor inherited by this object.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### source_file

Type: string

Source code file name metadata string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

## dex.MapList

### size

Type: uint32

Number of specific map item elements tracked.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### items

Type: array of dex.MapItem

Structured mapping descriptors detailing item positions.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

## dex.MapItem

### type

Type: dex.TypeCode

Standard item classification type code.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### unused

Type: uint32

Reserved unused padding field.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### size

Type: uint32

Total count of individual items in this section.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### offset

Type: uint32

File offset marking the start of the designated items.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

## dex.TypeCode

### TYPE_HEADER_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_STRING_ID_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_TYPE_ID_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_PROTO_ID_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_FIELD_ID_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_METHOD_ID_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_CLASS_DEF_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_CALL_SITE_ID_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_METHOD_HANDLE_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_MAP_LIST

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_TYPE_LIST

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_ANNOTATION_SET_REF_LIST

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_ANNOTATION_SET_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_CLASS_DATA_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_CODE_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_STRING_DATA_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_DEBUG_INFO_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_ANNOTATION_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_ENCODED_ARRAY_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_ANNOTATIONS_DIRECTORY_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

### TYPE_HIDDENAPI_CLASS_DATA_ITEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/dex.proto

## dex.checksum()

Return type: Option<i64>

Function that returns the Adler32 checksum for the current DEX file.

This is useful for comparing with checksum appearing in the DEX header
(dex.header.checksum) in order to verify if the actual checksum matches
the one in the header.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/dex/mod.rs#L42

## dex.signature()

Return type: Option<Lowercase<FixedLenString<40>>>

Function that return the sha1 signature for the current DEX file.

This is useful for comparing with signature appearing in the DEX header
(dex.header.signature) in order to verify if the actual signature matches
the on in the header.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/dex/mod.rs#L77

## dex.contains_string(value: RuntimeString)

Return type: Option<bool>

Function that checks whether the DEX file contains the specified string

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/dex/mod.rs#L113

## dex.contains_method(value: RuntimeString)

Return type: Option<bool>

Function that checks whether the DEX file contains the specified method

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/dex/mod.rs#L127

## dex.contains_class(value: RuntimeString)

Return type: Option<bool>

Function that checks whether the DEX file contains the specified class

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/dex/mod.rs#L143
