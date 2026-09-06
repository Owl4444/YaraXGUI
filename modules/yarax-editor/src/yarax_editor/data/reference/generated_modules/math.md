# math — YARA-X 1.20.0

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/math.proto

Generated from the official protobuf definitions and Rust exports. Availability depends on the engine build and field feature restrictions.

## math.Math

### MEAN_BYTES

Type: float

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/math.proto

## math.min(a: i64, b: i64)

Return type: i64

Returns the minimum of two integers.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L30

## math.max(a: i64, b: i64)

Return type: i64

Returns the maximum of two integers.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L36

## math.abs(x: i64)

Return type: i64

Returns the absolute value of an integer.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L42

## math.in_range(x: f64, min: f64, max: f64)

Return type: bool

Returns true if the given float is mostly within the [min, max] range.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L48

## math.in_range(x: i64, min: i64, max: i64)

Return type: bool

Returns true if the given int is within the [min, max] range.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L54

## math.to_string(x: i64)

Return type: RuntimeString

Converts an integer to a string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L60

## math.to_string(x: i64, base: i64)

Return type: Option<RuntimeString>

Converts an integer to a string in the given base.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L66

## math.to_number(b: bool)

Return type: i64

Converts a boolean to an integer (0 or 1).

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L81

## math.count(byte: i64, offset: i64, length: i64)

Return type: Option<i64>

Counts the occurrences of a byte in a range of the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L87

## math.count(byte: i64)

Return type: Option<i64>

Counts the occurrences of a byte in the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L154

## math.percentage(byte: i64)

Return type: Option<f64>

Returns the percentage of occurrences of a byte in the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L104

## math.percentage(byte: i64, offset: i64, length: i64)

Return type: Option<f64>

Returns the percentage of occurrences of a byte in a range of the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L116

## math.mode()

Return type: Option<i64>

Returns the most frequent byte in the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L137

## math.mode(offset: i64, length: i64)

Return type: Option<i64>

Returns the most frequent byte in a range of the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L145

## math.entropy(offset: i64, length: i64)

Return type: Option<f64>

Calculates the entropy of a range of the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L161

## math.entropy(s: RuntimeString)

Return type: Option<f64>

Calculates the entropy of a string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L170

## math.deviation(offset: i64, length: i64, mean: f64)

Return type: Option<f64>

Calculates the deviation of a range of the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L176

## math.deviation(s: RuntimeString, mean: f64)

Return type: Option<f64>

Calculates the deviation of a string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L190

## math.mean(offset: i64, length: i64)

Return type: Option<f64>

Calculates the mean of a range of the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L200

## math.mean(s: RuntimeString)

Return type: Option<f64>

Calculates the mean of a string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L209

## math.serial_correlation(offset: i64, length: i64)

Return type: Option<f64>

Calculates the serial correlation of a range of the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L215

## math.serial_correlation(s: RuntimeString)

Return type: Option<f64>

Calculates the serial correlation of a string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L229

## math.monte_carlo_pi(offset: i64, length: i64)

Return type: Option<f64>

Calculates the Monte Carlo Pi approximation of a range of the scanned data.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L238

## math.monte_carlo_pi(s: RuntimeString)

Return type: Option<f64>

Calculates the Monte Carlo Pi approximation of a string.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/math.rs#L252
