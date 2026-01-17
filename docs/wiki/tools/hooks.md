# HOOKS Tool Manual

API hook suggestions and script generation for dynamic analysis.

## Actions
### Supported Actions
- suggest
- generate_frida
- generate_detours
- find_targets
- inline_hooks


### `suggest`
Suggest hook points based on analysis.
Scans for interesting API calls (Networking, Registry, File I/O) and suggests points to hook.

### `generate_frida`
Generate a Frida hook script.
Generates a boilerplate JavaScript script for Frida.

### `generate_detours`
Generate a Detours hook scaffold.
Generates a C++ template for Microsoft Detours.

### `find_targets`
Find likely hook targets.
Locates indirect calls and vtable entries that are prime candidates for interception.

### `inline_hooks`
Suggest inline hook locations.
Identifies safe locations for instruction trampolines.

## Best Practices
Generate a Frida script for the `recv` or `ReadFile` functions to see the data flow in real-time while you reverse the logic in IDA.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
