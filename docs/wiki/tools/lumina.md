# lumina

Interfaces with IDA's Lumina server for function signature sharing and metadata.

## Actions
- `pull` — pull known function metadata from Lumina; params: `address` (optional)
- `push` — push function metadata to Lumina; params: `address` (optional)
- `status` — check Lumina connection status
- `history` — view push/pull history
- `search` — search Lumina for a function; params: `query`
- `get_metadata` — get Lumina metadata for address; params: `address`

## Examples
```json
{"name": "lumina", "arguments": {"action": "pull"}}
```
```json
{"name": "lumina", "arguments": {"action": "search", "query": "AES_encrypt"}}
```

## Notes
- Requires Lumina server connectivity (configured in IDA).
- `pull`/`push` without address operates on all functions.
