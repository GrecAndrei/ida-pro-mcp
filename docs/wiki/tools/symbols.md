# symbols

Loads, applies, and exports debug symbol information (PDB, DWARF).

## Actions
- `load_pdb` — load a PDB file; params: `path`
- `load_dwarf` — load DWARF debug info; params: `path` (optional)
- `status` — check current symbol loading status
- `apply` — re-apply type info to a function; params: `address`
- `export` — export symbols; params: `path`, `format` (optional)

## Examples
```json
{"name": "symbols", "arguments": {"action": "load_pdb", "path": "/path/to/binary.pdb"}}
```
```json
{"name": "symbols", "arguments": {"action": "apply", "address": "0x401000"}}
```

## Notes
- `load_pdb` now correctly uses the provided path (fixed in recent versions).
- `apply` re-applies type info and falls back to TIL lookup if PDB types are unavailable.
- `export` supports IDC, MAP, and other formats.
