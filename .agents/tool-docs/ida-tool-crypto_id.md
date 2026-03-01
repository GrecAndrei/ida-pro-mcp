# IDA MCP Tool Doc: `crypto_id`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `crypto_id` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Crypto algorithm identification via known constants (AES S-box, SHA-256, CRC32, etc). Actions: identify, constants, key_schedule, block_cipher, hash_detect, rng_detect, asymmetric, custom_crypto, encoding, checksums.

## Actions
- `identify`
- `constants`
- `key_schedule`
- `block_cipher`
- `hash_detect`
- `rng_detect`
- `asymmetric`
- `custom_crypto`
- `encoding`
- `checksums`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
