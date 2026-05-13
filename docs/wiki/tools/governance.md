# governance

Deterministic rule-based validation layer for safe writes: patches, renames, comments, and type changes.

## Actions
- `check` — pre-flight validation. Params: `operation` (rename|comment|patch|type), `address`, `value`. Detects PII, dangerous patches, contradictions, misleading claims.
- `redact` — redact sensitive content from a string. Params: `text`
- `list_rules` — list all active governance rules
- `stats` — governance statistics (checks run, violations caught)

## Examples
```json
{"name": "governance", "arguments": {"action": "check", "operation": "comment", "address": "0x401000", "value": "Decrypts AES key from registry"}}
```
```json
{"name": "governance", "arguments": {"action": "stats"}}
```

## Notes
- Call `check` before any write operation to catch issues early.
- Rules are deterministic (no LLM involved); they detect patterns like email addresses, absolute paths, and contradictory labels.
- Controlled by `_guardrail_mode`: `assist` (default warnings), `enforce` (blocks), `off`.
