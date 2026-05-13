# imports_deep

Deep analysis of import table entries: thunks, delay imports, forwarded exports, and API sets.

## Actions
- `thunks` — list import thunk functions
- `delay` — list delay-loaded imports
- `forwarded` — list forwarded exports
- `ordinal` — list ordinal-only imports
- `api_sets` — resolve Windows API set mappings
- `resolve` — resolve a specific import; params: `name` or `address`

## Examples
```json
{"name": "imports_deep", "arguments": {"action": "thunks"}}
```
```json
{"name": "imports_deep", "arguments": {"action": "resolve", "name": "CreateFileW"}}
```

## Notes
- `api_sets` is Windows-specific (resolves api-ms-win-* to actual DLLs).
- `delay` imports are loaded on first call, not at process start.
