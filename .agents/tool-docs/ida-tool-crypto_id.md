# IDA MCP Tool Doc: `crypto_id`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `crypto_id` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Crypto algorithm identification via known constants (AES S-box, SHA-256, CRC32, etc). Actions: identify, constants, key_schedule, block_cipher, hash_detect, rng_detect, asymmetric, custom_crypto, encoding, checksums.

## Actions
- `identify` (tool-specific)
- `constants` (tool-specific)
- `key_schedule` (tool-specific)
- `block_cipher` (tool-specific)
- `hash_detect` (tool-specific)
- `rng_detect` (tool-specific)
- `asymmetric` (tool-specific)
- `custom_crypto` (tool-specific)
- `encoding` (tool-specific)
- `checksums` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/crypto_id')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "crypto_id",
  "arguments": {
    "action": "identify"
  }
}
```
```json
{
  "name": "crypto_id",
  "arguments": {
    "action": "grep",
    "source_action": "identify",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
