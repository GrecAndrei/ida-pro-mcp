# CALC Tool Manual

Mathematical utilities and address resolution for reverse engineering.

## Actions
### Supported Actions
- eval
- offset
- convert
- resolve
- deref
- chain
- align


### `eval`
Evaluate a numeric expression with symbol resolution.
Evaluates a mathematical expression. Supports hex, binary, and C-style operators.
*   **Args**: `expr` (e.g. `0x100 + (1024 * 4)`).

### `offset`
Compute the delta between two addresses.
Calculates the relative offset between two addresses.

### `resolve`
Resolve VA and file offset information for an address.
Resolves a symbol name to its address or vice versa.

### `convert`
Convert numbers between hex, decimal, binary, and ASCII forms.
Converts values between formats (e.g. integer to IEEE754 float).

### `deref`
Dereference a typed value at an address.
Reads a typed value from memory (u8/u16/u32/u64/s8/s16/s32/s64/f32/f64/ptr/bytes/string).

### `chain`
Follow a pointer chain using a list of offsets.
Follows a pointer chain with offsets and returns each hop.

### `align`
Align a value to a boundary and return aligned results.
Aligns a value/address to a boundary and returns aligned up/down values.

## Strategy
Use `eval` when calculating buffer overflows or structural offsets. It prevents hallucination errors common in LLMs.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
