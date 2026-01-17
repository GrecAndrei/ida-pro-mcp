# PATTERNS Tool Manual

Generate and match function signatures (FLIRT-like patterns).

## Actions
### Supported Actions
- generate
- match
- list_sigs
- apply_sig
- create_sig


### `create_sig`
Create and save a signature.

### `generate`
Generate a signature from bytes.
Creates a hex pattern from a function, automatically wildcarding relocations and variable offsets.
*   **Args**: `addr`, `length` (default 32).
*   **Best for**: Creating signatures to find the same logic in other binaries.

### `match`
Match a signature against the database.
Searches the entire binary for functions matching a hex pattern (supports `??` wildcards).
*   **Args**: `pattern` (e.g. `55 89 E5 ?? 83 EC`).

### `list_sigs`
List available signatures.
Lists available `.sig` files in your IDA signature directory.

### `apply_sig`
Apply a signature to the database.
Plans to apply a FLIRT signature file. Analysis happens in the background.

## Strategy
Use `generate` on a known function (e.g. from a symbolic build), then use `match` on a stripped version of the same binary.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
