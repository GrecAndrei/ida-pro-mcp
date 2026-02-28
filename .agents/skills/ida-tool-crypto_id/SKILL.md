# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`crypto_id`

## Use This Skill When
- You need to call the `crypto_id` tool.
- You want exact action/parameter contract without scanning global tool metadata.

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

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
