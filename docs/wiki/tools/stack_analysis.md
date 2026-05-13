# stack_analysis

Analyze stack frame layout: buffers, canaries, variable types, and potential vulnerabilities.

## Actions
- `frame` — full stack frame layout for function at `address`.
- `buffers` — identify stack buffers (arrays/large locals) at `address`.
- `canary` — detect stack canary/cookie presence at `address`.
- `alignment` — check stack alignment properties at `address`.
- `spills` — identify register spill slots at `address`.
- `usage` — compute total stack usage (frame size + dynamic allocs) at `address`.
- `variables` — enumerate local variables with types/offsets at `address`.
- `arrays` — identify array-like stack allocations at `address`.
- `uninitialized` — detect potentially uninitialized stack variables at `address`.

## Examples
```json
{"name": "stack_analysis", "arguments": {"action": "frame", "address": "0x401000"}}
```
```json
{"name": "stack_analysis", "arguments": {"action": "buffers", "address": "0x401000"}}
```

## Notes
- `buffers` + `canary` together help assess buffer overflow exploitability.
- `uninitialized` flags variables read before write — useful for vuln hunting.
- All actions require a function start address.
