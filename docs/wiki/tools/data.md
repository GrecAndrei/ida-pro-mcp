# data

Queries structured data from the IDB: functions, globals, strings, imports, exports, and capability analysis.

## Actions
- `functions` — list functions. Optional `offset`, `count`, `filter`, `sort`
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
{"name": "data", "arguments": {"action": "lookup", "name": "main"}}
```

## Notes
- Paginate large results with `offset`/`count` to stay within context budget.
- `capability_matrix` is useful for initial triage without reading every function.
