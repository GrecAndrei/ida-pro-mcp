# nav

Navigates the IDA cursor and finds interesting locations.

## Actions
- `goto` — move cursor to address; params: `address`
- `cursor` — get current cursor position
- `interesting` — find interesting/notable addresses; params: `count` (optional)
- `semantic_goto` — navigate by semantic description; params: `description`

## Examples
```json
{"name": "nav", "arguments": {"action": "goto", "address": "0x401000"}}
```
```json
{"name": "nav", "arguments": {"action": "semantic_goto", "description": "main encryption function"}}
```

## Notes
- `semantic_goto` uses function names, strings, and comments to find the best match.
- `interesting` returns addresses ranked by significance signals from analysis context.
