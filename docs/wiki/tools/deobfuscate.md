# DEOBFUSCATE Tool Manual

## What It Does
LLM-optimized deobfuscation analysis for binary reverse engineering.

## Actions
- `detect_encoding`: Detect common encoding/packing transforms.
- `xor_scan`: Scan for XOR-obfuscated buffers/loops.
- `stack_strings`: Find stack string construction patterns.
- `opaque_predicates`: Detect likely opaque predicates.
- `control_flow_flatten`: Detect control-flow flattening patterns.
- `dead_code`: Find likely dead/unreachable code.
- `api_hashing`: Detect API hashing usage.
- `dynamic_dispatch`: Detect indirect dynamic dispatch patterns.
- `anti_disasm`: Detect anti-disassembly tricks.
- `decode_attempt`: Try decoding bytes at/near an address with a key.

## Key Parameters
- `action` (required): Operation selector.
- `addr` (default `None`): Target address or function start (hex string).
- `limit` (default `50`): Maximum result count.
- `key` (default `None`): Decode/deobfuscation key (often hex byte/string).
- `depth` (default `2`): Traversal/path depth bound.

## Examples (JSON call snippets)
```json
{
  "tool": "deobfuscate",
  "args": {
    "action": "detect_encoding",
    "addr": "0x401000",
    "limit": 50
  }
}
```
```json
{
  "tool": "deobfuscate",
  "args": {
    "action": "decode_attempt",
    "addr": "0x404200",
    "key": "0x5A",
    "limit": 32
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `addr required for decode_attempt`
- `INVALID_ARGS`: `Unknown action: {action}`
