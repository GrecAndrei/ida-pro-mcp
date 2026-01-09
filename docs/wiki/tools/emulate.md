# EMULATE Tool Manual

Code emulation and static execution tracing.

## Actions
### Supported Actions
- static_trace
- appcall
- decrypt_strings
- eval_expr


### `decrypt_strings`
Attempt to decode or decrypt strings.

### `static_trace`
Emulate a static trace from an address.
Perform a static walk through a function to see reachable paths without a debugger.

### `appcall`
Execute an appcall in IDA with arguments.
Calls a function inside the target process with specific arguments. **Requires an active debugger session.**
*   **Args**: `func_name` or `addr`, `args` (list).

### `eval_expr`
Evaluate an expression in the emulator context.
Evaluates a C-style expression in the current context.

## Best Practices
Use `appcall` to verify your understanding of an algorithm. "I think this decrypts data? Let me call it with a known encrypted buffer and check the return."
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
