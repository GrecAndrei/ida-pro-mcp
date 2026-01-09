# ENTROPY Tool Manual

Detect packed, encrypted, or obfuscated code and data regions.

## Actions
### Supported Actions
- section
- region
- packed_detect
- crypto_detect
- compare


### `compare`
Compare entropy between regions.

### `section`
Compute entropy for each section.
Calculates entropy for every segment in the binary. High entropy (>7.0) usually indicates compressed or encrypted data.

### `region`
Compute entropy for a specific region.
Calculates entropy for a specific address range.

### `packed_detect`
Detect packed regions using entropy heuristics.
Heuristic scan for common packer signatures and entry point patterns.

### `crypto_detect`
Detect crypto-like regions using entropy heuristics.
Scans for cryptographic constants (S-boxes, magic numbers) for AES, SHA, etc.

## Strategy
Always run `section` on a fresh binary. If `.text` has high entropy, the file is packed. Stop and find the OEP (Original Entry Point).
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
