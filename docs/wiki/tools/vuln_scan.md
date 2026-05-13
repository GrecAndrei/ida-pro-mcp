# vuln_scan

**Legacy alias** — routes to `threat_hunt(action="vuln")`.

## Actions
- All actions are forwarded to `threat_hunt` with `action="vuln"`.

## Examples
```json
{"name": "threat_hunt", "arguments": {"action": "vuln", "address": "0x401000"}}
```

## Notes
- Do not use `vuln_scan` directly; use `threat_hunt(action="vuln")` instead.
- Kept for backward compatibility with older client configurations.
