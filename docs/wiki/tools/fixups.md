# fixups

Manages IDA fixup (relocation) entries in the database.

## Actions
- `list` — list all fixups; params: `start`, `end` (optional range)
- `get` — get fixup at address; params: `address`
- `add` — add a fixup entry; params: `address`, `type`, `target`
- `delete` — delete a fixup; params: `address`

## Examples
```json
{"name": "fixups", "arguments": {"action": "list"}}
```
```json
{"name": "fixups", "arguments": {"action": "add", "address": "0x401000", "type": "off32", "target": "0x404000"}}
```

## Notes
- Fixups represent relocation information used by the loader.
- Modifying fixups can affect cross-reference analysis.
