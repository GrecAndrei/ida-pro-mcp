# analysis

Controls IDA's auto-analysis engine options and triggers reanalysis.

## Actions
- `get_options` — retrieve current analysis options
- `set_options` — set analysis options; params: `options` (dict)
- `set_processor` — change processor module; params: `processor`
- `set_loader_options` — configure loader; params: `options` (dict)
- `set_architecture` — set target architecture; params: `arch`, `bits`
- `reanalyze` — trigger full reanalysis; params: `address` (optional, scope)

## Examples
```json
{"name": "analysis", "arguments": {"action": "get_options"}}
```
```json
{"name": "analysis", "arguments": {"action": "reanalyze", "address": "0x401000"}}
```

## Notes
- `set_processor` and `set_architecture` are typically used once at session creation.
- `reanalyze` without an address triggers a full database reanalysis.
