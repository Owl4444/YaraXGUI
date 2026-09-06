# hash — YARA-X 1.20.0

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/hash.proto

Generated from the official protobuf definitions and Rust exports. Availability depends on the engine build and field feature restrictions.

## hash.Hash

## hash.md5(offset: i64, size: i64)

Return type: Option<Lowercase<FixedLenString<32>>>

Calculates the MD5 hash of a portion of the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/hash/mod.rs#L44

## hash.md5(s: RuntimeString)

Return type: Option<Lowercase<FixedLenString<32>>>

Calculates the MD5 hash of a string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/hash/mod.rs#L77

## hash.sha1(offset: i64, size: i64)

Return type: Option<Lowercase<FixedLenString<40>>>

Calculates the SHA-1 hash of a portion of the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/hash/mod.rs#L92

## hash.sha1(s: RuntimeString)

Return type: Option<Lowercase<FixedLenString<40>>>

Calculates the SHA-1 hash of a string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/hash/mod.rs#L125

## hash.sha256(offset: i64, size: i64)

Return type: Option<Lowercase<FixedLenString<64>>>

Calculates the SHA-256 hash of a portion of the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/hash/mod.rs#L140

## hash.sha256(s: RuntimeString)

Return type: Option<Lowercase<FixedLenString<64>>>

Calculates the SHA-256 hash of a string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/hash/mod.rs#L173

## hash.crc32(offset: i64, size: i64)

Return type: Option<i64>

Calculates the CRC32 checksum of a portion of the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/hash/mod.rs#L188

## hash.crc32(s: RuntimeString)

Return type: Option<i64>

Calculates the CRC32 checksum of a string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/hash/mod.rs#L210

## hash.checksum32(offset: i64, size: i64)

Return type: Option<i64>

Calculates the 32-bit checksum of a portion of the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/hash/mod.rs#L238

## hash.checksum32(s: RuntimeString)

Return type: Option<i64>

Calculates the 32-bit checksum of a string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/hash/mod.rs#L260
