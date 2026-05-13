# hooks

Generates hooking code (Frida, Detours, inline) and suggests hook targets.

## Actions
- `suggest` — suggest interesting hook targets; params: `criteria` (optional)
- `generate_frida` — generate Frida hook script; params: `address`, `action_type` (optional)
- `generate_detours` — generate Microsoft Detours code; params: `address`
- `find_targets` — find hookable targets by pattern; params: `pattern`
- `inline_hooks` — detect existing inline hooks; params: `address` (optional)

## Examples
```json
{"name": "hooks", "arguments": {"action": "generate_frida", "address": "0x401000"}}
```
```json
{"name": "hooks", "arguments": {"action": "suggest"}}
```

## Notes
- Generated Frida scripts include argument/return logging by default.
- `inline_hooks` detects JMP patches and trampolines in existing code.
