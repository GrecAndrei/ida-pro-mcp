# COLORIZE Tool Manual

## What It Does
Apply visual coloring to the database.

## Actions
- `set_func`: Apply a color to a function.
- `set_range`: Apply a color to an address range.
- `set_insn`: Apply a color to one instruction.
- `get`: Read color state at an address.
- `clear`: Clear color at an address/range/function.
- `palette`: Return known color names/palette mapping.
- `highlight_pattern`: Color all matches for a byte/text pattern.

## Key Parameters
- `action` (required): Operation selector.
- `addr` (default `None`): Target address or function start (hex string).
- `end_addr` (default `None`): Range end address for color operations.
- `color` (default `None`): Color name/value used by coloring or highlighting actions.
- `pattern` (default `None`): Byte/text pattern for `highlight_pattern`.

## Examples (JSON call snippets)
```json
{
  "tool": "colorize",
  "args": {
    "action": "set_range",
    "addr": "0x401000",
    "end_addr": "0x401080",
    "color": "orange"
  }
}
```
```json
{
  "tool": "colorize",
  "args": {
    "action": "highlight_pattern",
    "pattern": "55 8B EC",
    "color": "cyan"
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `addr required`
- `INVALID_ARGS`: `addr and end_addr required`
- `INVALID_ARGS`: `pattern required`
- `INVALID_ARGS`: `Invalid pattern`
- `INVALID_ARGS`: `Unknown action: {action}`
