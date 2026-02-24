# DIFF Tool Manual

## What It Does
Performs in-database binary comparison tasks: function pseudocode diffs, byte-range diffs, fuzzy signature matching, and BinExport triggering.

## Actions
- `functions`: Decompile two functions and return similarity plus unified diff lines.
- `bytes`: Compare two ranges (`start:end` format) byte-by-byte.
- `signatures`: Find similar functions to a target using fuzzy byte matching.
- `summary`: Return coarse DB metrics (`funcs`, `names`, `segs`).
- `export_binexport`: Trigger BinExport plugin workflow.

## Key Parameters
- `action`: One of `functions|bytes|signatures|summary|export_binexport`.
- `addr1`, `addr2`:
  - `functions`: function addresses.
  - `bytes`: range strings like `0x401000:0x401100`.
  - `signatures`: `addr1` is required target function.
- `threshold`: Similarity cutoff for `signatures` (default `0.8`).
- `path`: Required by `export_binexport`; validated as safe path.

## Examples
```python
diff(action="functions", addr1="0x401000", addr2="0x402000")
diff(action="bytes", addr1="0x401000:0x401080", addr2="0x501000:0x501080")
diff(action="signatures", addr1="0x401000", threshold=0.9)
diff(action="summary")
diff(action="export_binexport", path="/tmp/sample.BinExport")
```

## Failure Modes
- Missing required addresses (`addr1`, `addr2`) for comparison actions.
- Invalid `start:end` range syntax for `bytes`.
- Address not a function when `require_func=True` is enforced.
- BinExport plugin unavailable (`NOT_IMPLEMENTED`).
- Decompilation/read failures return IDA error payloads.
