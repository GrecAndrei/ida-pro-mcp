# data

Queries structured data from the IDB: functions, globals, strings, imports, exports, and capability analysis.

## Actions
- `functions` — list functions. Optional `offset`, `count`, `filter`, `sort`, `min_xrefs`, `structured` (default false: LLM-friendly text blobs; `true` returns raw row dicts)
- `globals` — list global variables. Optional `offset`, `count`
- `strings` — list defined strings. Optional `offset`, `count`, `min_length`
- `imports` — list imported functions grouped by library
- `exports` — list exported symbols
- `lookup` — look up a single symbol/address. Params: `name` or `address`
- `bulk_query` — query multiple addresses/names at once. Params: `items` (array)
- `capability_matrix` — high-level capability summary (crypto, network, file I/O, etc.)

## Examples
```json
{"name": "data", "arguments": {"action": "functions", "count": 20}}
```
```json
{"name": "data", "arguments": {"action": "functions", "min_xrefs": 2, "count": 50}}
```
```json
{"name": "data", "arguments": {"action": "lookup", "name": "main"}}
```

## Notes
- Paginate large results with `offset`/`count` to stay within context budget.
- `min_xrefs` (int) filters functions with at least N xrefs before counting. The `total` field reflects the filtered set, so you can tell whether there's more to paginate.
- Response shape is uniform across list actions: `{ok, items, total, offset, count}` (or `{ok, ...}` for non-list actions). Match on the envelope, not on `value.0`-style positional access.
- `capability_matrix` is useful for initial triage without reading every function.
