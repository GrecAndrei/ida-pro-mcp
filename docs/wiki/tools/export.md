# export

Writes **real files** from the current IDB. Every successful export returns `path` (and usually `exported: true`).

## Actions

| Action | Writes | Notes |
| --- | --- | --- |
| `listing` | `.lst` | Optional `addr` or `start:end` |
| `html` | `.html` | Function + string report |
| `idc` | `.idc` | Names, functions, comments, types |
| `json` | `.json` | Metadata; optional `include_decompile` |
| `sarif` | `.sarif.json` | **Blackboard findings only** — empty if none written |
| `binexport` | `.BinExport` or fallback JSON | Uses `BinExportBinary("path")` when plugin present |
| `headers` | `.h` | C decls from local type library |
| `redact` | optional `out_path` | Pass `text=` or redacts binary strings |
| `vtable` | `.json` | Optional `query` name filter |

## Examples

```json
{"name":"export","arguments":{"action":"json","path":"/tmp/analysis.json"}}
```

```json
{"name":"export","arguments":{"action":"binexport","path":"/tmp/app.BinExport"}}
```

```json
{"name":"export","arguments":{"action":"headers","path":"/tmp/types.h"}}
```

```json
{"name":"export","arguments":{"action":"redact","text":"contact admin@example.com at 10.0.0.1"}}
```

## Notes

- Always pass an explicit writable `path` when you care about location.
- If BinExport plugin is missing, response has `fallback: true` and a **JSON** path — not a real BinExport protobuf. Use `bindiff(action='snapshot')` for cross-version work without the plugin.
- SARIF is honest: no fake “finding per function.”