# deobfuscate

Detects and decodes obfuscation techniques including stack strings, API hashing, dead code, and encoding layers.

## Actions
- `detect` — detect obfuscation techniques using BehaviorClassifier + deterministic checks; params: `address` (optional, whole-binary if omitted)
- `detect_encoding` — identify encoding/encryption layers; params: `address`
- `stack_strings` — extract stack-constructed strings; params: `address`, `min_length`
- `dead_code` — identify dead/unreachable code regions; params: `address`
- `api_hashing` — detect and resolve API hash lookups; params: `address`
- `dynamic_dispatch` — identify dynamic dispatch / indirect call patterns; params: `address`
- `anti_disasm` — detect anti-disassembly tricks; params: `address`
- `decode_attempt` — attempt automatic decoding of obfuscated data; params: `address`, `length`

## Examples

```json
{"name": "deobfuscate", "arguments": {"action": "detect"}}
```

```json
{"name": "deobfuscate", "arguments": {"action": "stack_strings", "address": "0x401000"}}
```

## Notes
- `detect` uses BehaviorClassifier with obfuscation anchors (obfuscation_xor, stack_strings, api_hashing) plus anti_debug/anti_vm deterministic checks.
- Results from `deobfuscate` are auto-captured to the blackboard for persistent tracking.
- `api_hashing` attempts to resolve hashes against known API hash databases (CRC32, ROR13, etc.).
