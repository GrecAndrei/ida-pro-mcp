# STRINGS_XREF Tool Manual

Advanced string analysis with cross-reference chains.

## Actions
### Supported Actions
- analyze
- xref_chain
- detect_encoded
- find_format
- clusters


### `clusters`
Cluster related strings.

### `analyze`
Run a comprehensive function analysis bundle.
Deep analysis of a string at `addr`. Shows its encoding and raw bytes.
*   **Args**: `addr` (optional). If omitted, returns a global summary of the most referenced strings.

### `xref_chain`
Follow string xrefs across callsites.
Traces where a string is used through multiple levels of callers.
*   **Args**: `addr` (optional), `depth`. If `addr` is omitted, suggests top-referenced strings as starting points.

### `detect_encoded`
Detect encoded strings.
Scans for strings that look like they might be Base64, XORed, or otherwise obfuscated.

### `find_format`
Find format strings and usage.
Locates format strings (e.g. `%s %d`) and identifies their arguments.

## Strategy
When reversing malware, use `detect_encoded` to find the decryption routines.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
