# string — YARA-X 1.20.0

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/string.proto

Generated from the official protobuf definitions and Rust exports. Availability depends on the engine build and field feature restrictions.

## string.String

## string.to_int(string: RuntimeString)

Return type: Option<i64>

Converts a string to an integer.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/string.rs#L10

## string.to_int(string: RuntimeString, base: i64)

Return type: Option<i64>

Converts a string to an integer in the given base.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/string.rs#L17

## string.length(string: RuntimeString)

Return type: Option<i64>

Returns the length of the string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/string.rs#L32
