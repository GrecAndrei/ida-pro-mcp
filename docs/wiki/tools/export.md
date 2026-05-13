# export

Exports IDB content in various formats for external consumption.

## Actions
- `listing` — generate ASM listing file. Optional `path`, `address`, `count`
- `html` — export as HTML. Optional `path`, `address`, `count`
- `idc` — export as IDC script. Optional `path`
- `json` — export structured JSON. Optional `path`, `scope`
- `binexport` — export in BinExport format (for BinDiff). Optional `path`
- `headers` — export C headers for all types. Optional `path`

## Examples
```json
{"name": "export", "arguments": {"action": "json", "path": "/tmp/analysis.json"}}
```
```json
{"name": "export", "arguments": {"action": "headers", "path": "/tmp/types.h"}}
```

## Notes
- Pass explicit writable `path` to avoid permission errors.
- `binexport` requires the BinExport plugin to be available.
- Default export location is the session cache directory.
