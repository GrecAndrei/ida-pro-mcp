# EXPORT Tool Manual

Export the IDA database or its metadata into various formats.

## Actions
### Supported Actions
- listing
- html
- idc
- json
- binexport
- headers


### `idc`
Export or evaluate IDC.

### `listing`
Export a text listing.
Generates a complete assembly listing (.lst).

### `html`
Export an HTML listing.
Generates an interactive HTML report of the analysis.

### `json`
Export JSON data.
Exports all names, xrefs, and function metadata as a JSON file.

### `binexport`
Export BinExport data if available.
Generates a Google BinExport (.BinExport) file for use with BinDiff.

### `headers`
Export C header prototypes.
Exports all defined structures and enums as C header files (.h).

## Best Practices
Use `json` to save your progress in a format that can be parsed by other automation tools or external AIs.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
