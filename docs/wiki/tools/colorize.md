# colorize

Sets and queries background colors for functions, ranges, and instructions in IDA.

## Actions
- `set_func` — color an entire function; params: `address`, `color`
- `set_range` — color an address range; params: `start`, `end`, `color`
- `set_insn` — color a single instruction; params: `address`, `color`
- `get` — get current color at address; params: `address`
- `clear` — remove coloring; params: `address` or `start`/`end`
- `palette` — list available named colors
- `highlight_pattern` — color all matches of a pattern; params: `pattern`, `color`

## Examples
```json
{"name": "colorize", "arguments": {"action": "set_func", "address": "0x401000", "color": "0xCCFFCC"}}
```
```json
{"name": "colorize", "arguments": {"action": "highlight_pattern", "pattern": "xor eax, eax", "color": "yellow"}}
```

## Notes
- Colors are RGB hex values or named palette entries.
- `highlight_pattern` is useful for visually marking suspicious instruction patterns.
