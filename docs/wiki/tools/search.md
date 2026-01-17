# SEARCH Tool Manual

High-speed pattern and reference searching.

Supports pagination via `offset` and `limit` for large result sets.

## Actions
### Supported Actions
- bytes
- string
- immediate
- name
- insns
- text
- operand
- comment
- data_ref
- code_ref


### `name`
Search for symbol names.

### `insns`
Search for instruction sequences.

### `text`
Search disassembly text.

### `operand`
Search operand text.

### `comment`
Create or update a comment at the specified address.

### `code_ref`
Find code references to an address.

### `bytes`
Diff or search raw byte patterns.
Search for hex patterns (supports `??` wildcards).
*   **Best for**: Finding magic numbers or known byte sequences.

### `string`
Search for string literals.
Universal text search. 
*   **Strategy**: Use this to find UI strings or error messages that hint at logic.

### `immediate`
Search for immediate values.
Finds numeric constants (e.g. `0x1337`). 
*   **Note**: In IDA 9.2, this uses a robust manual scan to ensure no constants are missed.

### `data_ref` / `code_ref`
Find data references to an address.
Finds all references to an address.
*   **Strategy**: "Who uses this global variable?" or "Who calls this function?"
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
