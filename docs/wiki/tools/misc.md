# MISC Tool Manual

Advanced utilities for Python/IDC execution and bookmarking.

## Actions
### Supported Actions
- python
- idc
- load_sig


### `python`
Execute IDAPython and return output.
Executes an arbitrary Python script inside the IDA process. **DANGEROUS.**

### `idc`
Export or evaluate IDC.
Executes an IDC script.

### `load_sig`
Load a signature file.
Loads a FLIRT signature file (.sig).

## Best Practices
Only use `python` if a specialized tool (like `modify` or `structs`) doesn't exist for your task. It is the most powerful but least safe tool in the set.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
