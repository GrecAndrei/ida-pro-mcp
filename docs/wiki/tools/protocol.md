# protocol

Detects and analyzes network protocol implementations, parsers, and state machines in binary code.

## Actions
- `detect` — Classify protocol usage via BehaviorClassifier with protocol anchors; params: `address`
- `parsers` — Find protocol parsing routines; params: `protocol`, `address`
- `serializers` — Find serialization/marshalling code; params: `protocol`, `address`
- `handlers` — Identify message/command handler dispatch tables; params: `address`
- `endpoints` — Locate network endpoint setup (bind, connect, listen); params: `address`
- `tls_config` — Extract TLS/SSL configuration and cipher suite usage; params: `address`
- `socket_flow` — Trace socket lifecycle (create → connect → send → recv → close); params: `address`
- `packet_struct` — Infer packet structure from parsing code; params: `address`
- `magic_numbers` — Find protocol magic number checks; params: `address`
- `state_machine` — Reconstruct protocol state machine from handler transitions; params: `address`

## Examples
```json
{"name": "protocol", "arguments": {"action": "detect"}}
```
```json
{"name": "protocol", "arguments": {"action": "tls_config", "address": "0x404500"}}
```

## Notes
- `detect` uses anchors: `http_protocol`, `tls_ssl`, `custom_binary`, `dns_protocol`, `smtp_ftp`.
- `detect` accepts `query` and returns `query_protocol_hints` from embedding/classifier intent matching when available.
- Combine with `string_ops(action="find_urls")` and `imports_deep` for full network surface mapping.
- `state_machine` works best on binaries with clear handler dispatch patterns.
