# TRACE Tool Manual

Debugger tracing control and sequence management.

## Actions
### Supported Actions
- get
- clear
- set_options


### `set_options`
Set analysis info attributes such as base and bounds.
Configures tracing modes: instruction, function, or basic block.

### `get`
Retrieve a detailed view for the requested item or address.
Retrieves the current execution trace as a list of addresses.

### `clear`
Clear colorization for a target.
Clears the current trace buffer.

## Strategy
Combine with `trace_analysis` to find hot loops and logic paths.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
