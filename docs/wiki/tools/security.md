# security

Unified security analysis for packing, obfuscation, cryptography, protocols,
instrumentation, and taint paths.

## Actions

- `detect` — run a combined packer, entropy, crypto, and obfuscation sweep
- `decode` — decode bytes at `addr` using XOR, Base64, or an optional `key`
- `analyze` — inspect a specific target selected with `what`
- `hook` — generate Frida, Detours, or inline instrumentation
- `hook_targets` — find hookable functions, optionally by `category`
- `protocol` — detect protocol usage
- `protocol_spec` — recover a protocol component selected with `what`
- `taint` — trace a source or address to dangerous sinks
- `taint_sources` — list known taint sources
- `taint_report` — generate a complete source-to-sink report
- `eval` — run custom analysis Python with the security helpers and IDA SDK

## Examples

```json
{"name": "security", "arguments": {"action": "detect"}}
```

```json
{"name": "security", "arguments": {"action": "analyze", "what": "crypto_constants"}}
```

```json
{"name": "security", "arguments": {"action": "protocol_spec", "what": "parsers"}}
```

```json
{"name": "security", "arguments": {"action": "taint", "source": "recv"}}
```
