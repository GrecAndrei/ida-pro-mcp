# string_ops

Extracts, decodes, and classifies strings for IOC discovery and C2 scoring.

## Actions
- `decode_all` — Attempt decoding of obfuscated/encoded strings (XOR, base64, stack strings); params: `address`
- `find_urls` — Extract URL-like strings; params: `pattern`
- `find_paths` — Extract file system paths; params: `pattern`
- `find_registry` — Extract Windows registry key references; params: `pattern`
- `find_ips` — Extract IP addresses (IPv4/IPv6); params: `pattern`
- `find_emails` — Extract email addresses; params: `pattern`
- `find_commands` — Extract shell/command-line strings; params: `pattern`
- `encoding_stats` — Report encoding distribution across all strings (ASCII, UTF-8, wide, etc.)
- `score_c2` — Score strings for C2/beaconing indicators; params: `threshold`
- `api_triads` — Find suspicious API call triads (e.g., VirtualAlloc+WriteProcessMemory+CreateRemoteThread)

## Examples
```json
{"name": "string_ops", "arguments": {"action": "find_urls"}}
```
```json
{"name": "string_ops", "arguments": {"action": "score_c2", "threshold": 0.7}}
```

## Notes
- `score_c2` and `api_triads` are useful for quick malware triage before running full `threat_hunt`.
- All `find_*` actions support optional `pattern` for regex filtering.
- Pair with `crypto_id(action="encoding")` for deeper obfuscation analysis.
