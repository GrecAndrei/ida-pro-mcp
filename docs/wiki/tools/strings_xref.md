# STRINGS_XREF Tool Manual

## What It Does
Analyzes strings and their cross-reference behavior, including caller-chain tracing, encoded-string heuristics, format-string detection, and per-function string clustering.

## Actions
- `analyze`: Analyze one string (`addr`) or global top-referenced string summary.
- `xref_chain`: Trace reference chain upward by depth from a string.
- `detect_encoded`: Find strings with high-entropy/encoded-like traits.
- `find_format`: Find printf-style format strings and argument counts.
- `clusters`: Group strings by referencing functions.

## Key Parameters
- `action`: One of `analyze|xref_chain|detect_encoded|find_format|clusters`.
- `addr`: String/function address for scoped actions.
- `query`: Optional text filter used by `find_format`.
- `depth`: Recursion depth for `xref_chain` (default `3`).

## Examples
```python
strings_xref(action="analyze", addr="0x406000")
strings_xref(action="analyze")
strings_xref(action="xref_chain", addr="0x406000", depth=4)
strings_xref(action="find_format", query="error")
strings_xref(action="clusters")
```

## Failure Modes
- `analyze` returns address error when target is not a defined string.
- Invalid `addr` handling errors in address-parsing paths.
- `xref_chain` output can be sparse when references are indirect or not recovered.
