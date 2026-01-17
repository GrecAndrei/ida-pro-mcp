# SYMBOLS Tool Manual

Load and manage debug symbols (PDB, DWARF, COFF).

## Actions
### Supported Actions
- load_pdb
- load_dwarf
- status
- apply
- export


### `load_dwarf`
Load DWARF symbols.

### `load_pdb`
Load PDB symbols.
Loads a Windows PDB file. 
*   **Args**: `path` (optional). If omitted, IDA attempts to auto-detect and download from the symbol server.

### `status`
Report current status and availability.
Checks if debug symbols are currently loaded and reports function/type counts.

### `export`
Export tool output in the requested format.
Saves all named symbols and their types to a JSON file.
*   **Best for**: Migrating analysis between different IDA versions or versions of the same binary.

### `apply`
Apply a struct or symbols at an address.
Infers and applies type information from loaded symbols to a specific address.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
