# CALC Tool Manual

## What It Does
Address calculation and number conversion utilities (r2-style).

## Actions
- `eval`: Execute `eval` workflow.
- `offset`: Execute `offset` workflow.
- `convert`: Execute `convert` workflow.
- `resolve`: Execute `resolve` workflow.
- `deref`: Execute `deref` workflow.
- `chain`: Execute `chain` workflow.
- `align`: Execute `align` workflow.

## Key Parameters
- `action` (required): Operation selector.
- `expr` (default `None`): Expression string for calculator evaluation.
- `addr` (default `None`): Target address or function start (hex string).
- `target` (default `None`): Target address/symbol for resolve/xref/path actions.
- `value` (default `None`): Generic value parameter (setting, conversion, register write).
- `type` (default `None`): Conversion/data type selector.
- `size` (default `None`): Byte size / read length / data width, action-dependent.
- `offsets` (default `None`): Offset list for chained address calculation.

## Examples (JSON call snippets)
```json
{
  "tool": "calc",
  "args": {
    "action": "eval",
    "expr": "0x401000 + 0x30"
  }
}
```
```json
{
  "tool": "calc",
  "args": {
    "action": "chain",
    "addr": "0x404000",
    "offsets": [
      16,
      32,
      8
    ]
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `expr required`
- `INVALID_ARGS`: `Evaluation error: {expr} ({e})`
- `INVALID_ARGS`: `addr and target required`
- `INVALID_ARGS`: `value required`
- `INVALID_ARGS`: `addr required`
- `INVALID_ARGS`: `offsets required`
- `INVALID_ARGS`: `size (alignment) required`
- `INVALID_ARGS`: `Invalid alignment size`
