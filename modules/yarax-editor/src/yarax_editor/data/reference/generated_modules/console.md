# console — YARA-X 1.20.0

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/console.proto

Generated from the official protobuf definitions and Rust exports. Availability depends on the engine build and field feature restrictions.

## console.Console

## console.log(string: RuntimeString)

Return type: bool

Logs a string to the console.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/console.rs#L12

## console.log(message: RuntimeString, string: RuntimeString)

Return type: bool

Logs a string with a message to the console.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/console.rs#L19

## console.log(offset: i64, length: i64)

Return type: bool

See the linked upstream implementation.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/console.rs#L75

## console.log(message: RuntimeString, offset: i64, length: i64)

Return type: bool

See the linked upstream implementation.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/console.rs#L86

## console.log(b: bool)

Return type: bool

See the linked upstream implementation.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/console.rs#L103

## console.log(message: RuntimeString, b: bool)

Return type: bool

Logs a boolean value with a message to the console.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/console.rs#L110

## console.log(i: i64)

Return type: bool

Logs an integer value to the console.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/console.rs#L121

## console.log(message: RuntimeString, i: i64)

Return type: bool

Logs an integer value with a message to the console.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/console.rs#L128

## console.log(f: f64)

Return type: bool

Logs a float value to the console.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/console.rs#L135

## console.log(message: RuntimeString, f: f64)

Return type: bool

Logs a float value with a message to the console.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/console.rs#L142

## console.hex(i: i64)

Return type: bool

Logs an integer value as a hexadecimal string to the console.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/console.rs#L153

## console.hex(message: RuntimeString, i: i64)

Return type: bool

Logs an integer value as a hexadecimal string with a message to the console.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/console.rs#L160
