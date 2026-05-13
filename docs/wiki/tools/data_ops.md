# data_ops

Creates and modifies data items (bytes, arrays, strings, pointers) in the IDB.

## Actions
- `make_data` — define a data item; params: `address`, `type`, `size`
- `make_array` — define an array; params: `address`, `element_type`, `count`
- `make_string` — define a string; params: `address`, `string_type` (optional)
- `undefine` — undefine bytes; params: `address`, `size`
- `make_code` — convert to code; params: `address`
- `cycle_data` — cycle through data representations; params: `address`
- `set_repr` — set numeric representation (hex/dec/bin/char); params: `address`, `repr`
- `make_ptr` — define as pointer; params: `address`, `target` (optional)

## Examples
```json
{"name": "data_ops", "arguments": {"action": "make_string", "address": "0x404000"}}
```
```json
{"name": "data_ops", "arguments": {"action": "make_array", "address": "0x404100", "element_type": "dword", "count": 16}}
```

## Notes
- `make_code` triggers analysis on the converted region.
- `undefine` is required before redefining overlapping items.
