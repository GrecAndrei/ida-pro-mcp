# patterns

Generates, matches, and manages IDA signature patterns (FLIRT-style).

## Actions
- `generate` — generate a byte pattern for a function; params: `address`
- `match` — search for pattern matches; params: `pattern`
- `list_sigs` — list loaded signature files
- `apply_sig` — apply a signature file; params: `sig_name`
- `create_sig` — create a signature from functions; params: `addresses` (list), `name`
- `matched` — list functions matched by signatures

## Examples
```json
{"name": "patterns", "arguments": {"action": "generate", "address": "0x401000"}}
```
```json
{"name": "patterns", "arguments": {"action": "match", "pattern": "55 8B EC ?? ?? 83 C4"}}
```

## Notes
- Patterns use `??` for wildcard bytes.
- `create_sig` bundles multiple functions into a reusable signature file.
