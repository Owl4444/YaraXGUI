# olecf — YARA-X 1.20.0

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/olecf.proto

Generated from the official protobuf definitions and Rust exports. Availability depends on the engine build and field feature restrictions.

## olecf.Olecf

### is_olecf

Type: bool

True if file is an OLE CF file.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/olecf.proto

### streams

Type: array of olecf.Stream

Streams contained in the OLE CF file.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/olecf.proto

### StreamType

Type: olecf.Olecf.@StreamType

Constant namespace

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/olecf.proto

## olecf.Stream

### name

Type: string

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/olecf.proto

### type

Type: olecf.StreamType

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/olecf.proto

### size

Type: uint64

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/olecf.proto

## olecf.StreamType

### UNKNOWN

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/olecf.proto

### STORAGE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/olecf.proto

### STREAM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/olecf.proto

### ROOT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/olecf.proto

## olecf.Olecf.@StreamType

### UNKNOWN

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/olecf.proto

### STORAGE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/olecf.proto

### STREAM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/olecf.proto

### ROOT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/olecf.proto
