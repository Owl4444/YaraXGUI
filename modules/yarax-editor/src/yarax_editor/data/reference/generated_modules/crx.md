# crx — YARA-X 1.20.0

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

Generated from the official protobuf definitions and Rust exports. Availability depends on the engine build and field feature restrictions.

## crx.Crx

### is_crx

Type: bool

True if the file is a valid Chrome Extension (CRX) package.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### crx_version

Type: uint32

Format version of the CRX package.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### header_size

Type: uint32

Size in bytes of the binary CRX header.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### id

Type: string

Standard 32-character extension ID string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### version

Type: string

Extension version string extracted from the manifest.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### name

Type: string

Processed extension name extracted from the manifest.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### description

Type: string

Processed extension description extracted from the manifest.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### raw_name

Type: string

Raw unparsed extension name extracted from the manifest.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### raw_description

Type: string

Raw unparsed extension description extracted from the manifest.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### minimum_chrome_version

Type: string

Minimum Chrome version requirement string from the manifest.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### homepage_url

Type: string

Homepage URL string defined inside the manifest.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### permissions

Type: array of string

Required runtime permissions defined inside the manifest.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### host_permissions

Type: array of string

Required host access permissions defined inside the manifest.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### optional_permissions

Type: array of string

Optional runtime permissions defined inside the manifest.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### optional_host_permissions

Type: array of string

Optional host access permissions defined inside the manifest.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### signatures

Type: array of crx.CrxSignature

Cryptographic signatures validating the package.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

## crx.CrxSignature

### key

Type: string

Public key or identifier string used in the signature.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

### verified

Type: bool

True if the cryptographic signature successfully verified.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/crx.proto

## crx.permhash()

Return type: Option<Lowercase<FixedLenString<64>>>

Returns the SHA-256 hash of the permissions in the manifest.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/crx/mod.rs#L34
