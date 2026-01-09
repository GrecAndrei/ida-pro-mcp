# DIFF Tool Manual

Surgical differential analysis and fuzzy signature matching.

## Actions
### Supported Actions
- functions
- bytes
- signatures
- summary
- export_binexport


### `summary`
Return a high-level diff summary.

### `functions`
List functions with pagination and optional filtering.
Diffs two functions via their Hex-Rays pseudocode.
*   **Returns**: Similarity ratio (0.0-1.0) and unified diff lines.
*   **Best for**: Comparing a patched vs unpatched version of the same function.

### `signatures`
Diff or compare signatures between targets.
Finds similar functions in the current database using fuzzy byte matching.
*   **Args**: `addr1` (target), `threshold` (default 0.8).
*   **Strategy**: Uses size-based filtering for high-performance scanning.

### `export_binexport`
Export BinExport data if available.
Generates a `.BinExport` file. This is the bridge between IDA and BinDiff.
*   **Note**: Requires the BinExport plugin to be installed.

### `bytes`
Diff or search raw byte patterns.
Detailed byte-by-byte comparison of two memory ranges.
*   **Args**: `addr1` (range1), `addr2` (range2). Format: `"0x401000:0x401100"`.

## Strategy
When analyzing a patch, use `signatures` to find the corresponding function in the new binary, then `functions` to see exactly what logic changed.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
