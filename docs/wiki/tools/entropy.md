# ENTROPY Tool Manual

Detect packed, encrypted, or obfuscated code and data regions.

## Actions
### Supported Actions
- section
- region
- packed_detect
- crypto_detect
- compare
- window
- summary


### `compare`
Compare entropy between regions.
Use `addr`, `end_addr`, and `size` to compare two windows of equal length.

### `section`
Compute entropy for each section.
Calculates entropy for every segment in the binary. High entropy (>7.0) usually indicates compressed or encrypted data.
Includes sliding-window stats and high-entropy ratios.

### `region`
Compute entropy for a specific region.
Calculates entropy for a specific address range.
Returns a byte histogram and null-byte ratio.

### `packed_detect`
Detect packed regions using entropy heuristics.
Heuristic scan for high-entropy windows across segments.

### `crypto_detect`
Detect crypto-like regions using entropy heuristics.
Scans for cryptographic constants (S-boxes, magic numbers) for AES, SHA, etc.

### `window`
Sliding-window scan for a specific range.
Use with `addr`, `end_addr`, `window`, and `step` to zoom into suspicious ranges.

### `summary`
Summarize overall entropy across segments.

## Strategy
Always run `section` on a fresh binary. If `.text` has high entropy, the file is packed. Stop and find the OEP (Original Entry Point).
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
