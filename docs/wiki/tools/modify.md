# modify

Rename, comment, retype, and patch functions/addresses in the IDB with guardrail-protected writes.

## Actions
- `rename` — rename a function or address; params: `address`, `name`
- `comment` — set a comment; params: `address`, `comment`, `repeatable`
- `set_type` — set or change a type declaration; params: `address`, `type`
- `patch_asm` — patch assembly bytes; params: `address`, `asm` or `bytes`

## Examples

```json
{"name": "modify", "arguments": {"action": "rename", "address": "0x401000", "name": "decrypt_payload"}}
```

```json
{"name": "modify", "arguments": {"action": "comment", "address": "0x401000", "comment": "XOR key = 0x5A"}}
```

## Notes
- `rename` triggers background propagation: re-embeds the function, finds unnamed callees with high cosine similarity, and writes `rename_suggestion` entries to the blackboard.
- All write actions are subject to guardrails. In strict write mode (`IDA_MCP_GUARDRAIL_STRICT_WRITES`), calls are blocked unless `_guardrail_ack=true` is set.
- Use `governance(action="check")` for pre-flight validation before patches or renames to catch contradictions and dangerous changes.
