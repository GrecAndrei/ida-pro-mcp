# BINARY_INFO Tool Manual

## What It Does
Binary metadata and format analysis.

## Actions
- `headers`: Return file header details and format metadata.
- `sections`: List sections/segments with bounds and attributes.
- `relocations`: Summarize relocation information.
- `resources`: Enumerate embedded resources if present.
- `debug_info`: Report debug symbol information.
- `compiler`: Infer compiler/toolchain indicators.
- `linker`: Infer linker-related metadata.
- `timestamps`: Extract notable timestamp fields.
- `checksums`: Report available checksums/hashes.
- `overlay`: Detect and describe overlay/appended data.

## Key Parameters
- `action` (required): Operation selector.
- `addr` (default `None`): Target address or function start (hex string).
- `limit` (default `50`): Maximum result count.

## Examples (JSON call snippets)
```json
{
  "tool": "binary_info",
  "args": {
    "action": "headers"
  }
}
```
```json
{
  "tool": "binary_info",
  "args": {
    "action": "sections",
    "limit": 25
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `Unknown action: {action}`
