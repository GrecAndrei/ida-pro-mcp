# MICROCODE Tool Manual

Direct access to the Hex-Rays Microcode (mmat) intermediate representation.

## Actions
### Supported Actions
- get
- blocks
- instructions


### `get`
Retrieve a detailed view for the requested item or address.
Returns a summary of micro-blocks for a function.

### `blocks`
Return basic blocks for the target function.
Returns detailed instructions for each micro-block.

### `instructions`
Returns the full microcode instruction stream.

## Strategy
Use microcode when the C pseudocode is too high-level and you need to see exactly how compiler optimizations (like constant folding or dead code elimination) are affecting the logic.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
