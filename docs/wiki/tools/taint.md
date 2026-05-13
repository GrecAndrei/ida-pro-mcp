# taint

**Legacy alias** — routes to `threat_hunt(action="tracing")`.

## Actions
- All actions are forwarded to `threat_hunt` with `action="tracing"`.

## Examples
```json
{"name": "threat_hunt", "arguments": {"action": "tracing", "source": "0x401000", "sink": "0x402000"}}
```

## Notes
- Do not use `taint` directly; use `threat_hunt(action="tracing")` instead.
- Kept for backward compatibility with older client configurations.
