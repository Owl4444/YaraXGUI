# cuckoo — YARA-X 1.20.0

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/cuckoo.proto

Generated from the official protobuf definitions and Rust exports. Availability depends on the engine build and field feature restrictions.

## cuckoo.Cuckoo

## cuckoo.network.dns_lookup(regexp_id: RegexId)

Return type: i64

Returns true if the Cuckoo report contains a DNS lookup where the domain
matches the given regular expression.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/cuckoo/mod.rs#L52

## cuckoo.network.http_request(regexp_id: RegexId)

Return type: i64

Returns true if the Cuckoo report contains an HTTP request (either, GET,
or any other method) to some URI that matches the given regular expression.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/cuckoo/mod.rs#L71

## cuckoo.network.http_get(regexp_id: RegexId)

Return type: i64

Returns true if the Cuckoo report contains an HTTP GET request to some URI
that matches the given regular expression.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/cuckoo/mod.rs#L90

## cuckoo.network.http_post(regexp_id: RegexId)

Return type: i64

Returns true if the Cuckoo report contains an HTTP POST request to some URI
that matches the given regular expression.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/cuckoo/mod.rs#L112

## cuckoo.network.http_user_agent(regexp_id: RegexId)

Return type: i64

Returns true if the Cuckoo report contains an HTTP where the User-Agent
header matches the given regular expression.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/cuckoo/mod.rs#L134

## cuckoo.network.tcp(dst_re: RegexId, port: i64)

Return type: i64

Returns true if the Cuckoo report contains some TCP connection to the
destination `port` where the destination domain matches the given regular
expression

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/cuckoo/mod.rs#L154

## cuckoo.network.udp(dst_re: RegexId, port: i64)

Return type: i64

Returns true if the Cuckoo report contains some UDP connection to the
destination `port` where the destination domain matches the given regular
expression

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/cuckoo/mod.rs#L180

## cuckoo.network.host(re: RegexId)

Return type: i64

Returns true if the Cuckoo report contains an HTTP request where the Host
header matches the given regular expression.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/cuckoo/mod.rs#L203

## cuckoo.sync.mutex(mutex_re: RegexId)

Return type: i64

Returns true if the Cuckoo contains some mutex operation where the name
of the mutex matches the given regular expression.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/cuckoo/mod.rs#L220

## cuckoo.filesystem.file_access(regexp_id: RegexId)

Return type: i64

Returns true if the Cuckoo contains some file access operation where the
file path matches the given regular expression.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/cuckoo/mod.rs#L239

## cuckoo.registry.key_access(regexp_id: RegexId)

Return type: i64

Returns true if the Cuckoo contains some registry access operation where
the registry key matches the given regular expression.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/cuckoo/mod.rs#L258
