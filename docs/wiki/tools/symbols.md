# SYMBOLS Tool Manual

## What It Does
Loads and inspects debug-symbol information (PDB/DWARF), checks symbolization status, applies available type info to addresses, and exports symbol snapshots.

## Actions
- `load_pdb`: Trigger PDB loading (explicit `path` or auto-detect mode).
- `load_dwarf`: Trigger DWARF parsing plugin flow.
- `status`: Report named-function count and type-library count.
- `apply`: Return inferred type info for an address if available.
- `export`: Write discovered named symbols to JSON.

## Key Parameters
- `action`: One of `load_pdb|load_dwarf|status|apply|export`.
- `path`: Input symbol path (`load_pdb`) or output JSON path (`export`).
- `addr`: Required for `apply`.

## Examples
```python
symbols(action="load_pdb")
symbols(action="load_pdb", path="/symbols/app.pdb")
symbols(action="load_dwarf")
symbols(action="status")
symbols(action="apply", addr="0x401120")
symbols(action="export", path="/tmp/symbols.json")
```

## Failure Modes
- Missing required `path` or `addr` by action.
- Symbol plugin load failures from IDA (`PDB`/`DWARF`).
- `apply` may return no type if symbol data is unavailable at target address.
- Path validation failures for export destinations.
