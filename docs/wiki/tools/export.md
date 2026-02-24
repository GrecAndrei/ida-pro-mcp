# EXPORT Tool Manual

## What It Does
Exports analysis data into text/HTML/IDC/JSON/header formats and can trigger BinExport plugin output.

## Actions
- `listing`: Assembly listing export for a function/range/segment subset.
- `html`: Simple report with sampled functions and strings.
- `idc`: IDC script containing renames/comments.
- `json`: Structured metadata export (functions, strings, imports, exports).
- `binexport`: Trigger BinExport plugin action.
- `headers`: Export sampled type/struct info from local type library.

## Key Parameters
- `action`: One of `listing|html|idc|json|binexport|headers`.
- `path`: Output path (safe-path validated); defaults per action if omitted.
- `addr`: Optional for `listing`; supports `start:end` or address.
- `include_decompile`: Accepted parameter (currently not used by action logic).

## Examples
```python
export(action="listing", path="/tmp/sample.lst", addr="0x401000:0x402000")
export(action="html", path="/tmp/report.html")
export(action="idc", path="/tmp/reapply.idc")
export(action="json", path="/tmp/analysis.json")
export(action="binexport", path="/tmp/sample.BinExport")
export(action="headers", path="/tmp/types.h")
```

## Failure Modes
- Invalid or disallowed output path.
- Missing segments or unreadable address ranges for listing.
- BinExport plugin missing/failing.
- File write errors or API/version differences in type export.
