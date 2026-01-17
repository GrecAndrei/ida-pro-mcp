# COLORIZE Tool Manual

Visual highlighting and region coloring in the IDA UI.

## Actions
### Supported Actions
- set_func
- set_range
- set_insn
- get
- clear
- palette
- highlight_pattern


### `set_insn`
Colorize a single instruction.

### `get`
Retrieve a detailed view for the requested item or address.

### `palette`
List available color palette entries.

### `set_func`
Colorize a function.
Colors an entire function.
*   **Args**: `addr`, `color` (green|yellow|red|blue|etc.).

### `set_range`
Colorize a range of addresses.
Colors a specific address range.

### `clear`
Clear colorization for a target.
Removes all custom coloring from the database.

### `highlight_pattern`
Highlight addresses matching a pattern.
Searches for a byte pattern and colors all matches.

## Strategy
Color code your progress:
*   **Green**: Fully analyzed.
*   **Yellow**: Partially understood.
*   **Red**: Complex/Dangerous/Vulnerable.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
