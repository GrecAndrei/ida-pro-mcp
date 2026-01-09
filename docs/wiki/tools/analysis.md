# ANALYSIS Tool Manual

Processor/loader options and reanalysis control.

## Actions
### Supported Actions
- get_options
- set_options
- set_processor
- set_loader_options
- reanalyze

### `get_options`
Return key analysis and processor settings.
Returns current processor and analysis info (procname, filetype, bitness).

### `set_options`
Set analysis info attributes such as base and bounds.
Set basic info attributes such as `baseaddr`, `start_ea`, `min_ea`, `max_ea`.

### `set_processor`
Switch processor type for the current database.
Switch processor type using `idaapi.set_processor_type`.

### `set_loader_options`
Apply loader-specific options (if supported).
Apply loader-specific options (if supported by IDA version).

### `reanalyze`
Re-run auto-analysis over a specified range.
Re-run auto-analysis over a range (or entire image).
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
