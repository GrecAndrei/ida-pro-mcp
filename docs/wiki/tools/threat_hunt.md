# threat_hunt

Consolidated malware analysis, vulnerability scanning, and taint/tracing pipeline for binary threat assessment.

## Actions
- `run` — Run full threat hunt pipeline on current binary; params: `scope`, `depth`
- `malware` — Malware-focused analysis (C2 detection, packer ID, anti-analysis); params: `address`, `scope`
- `vuln` — Vulnerability scanning (buffer overflows, format strings, use-after-free); params: `address`, `pattern`
- `tracing` — Taint/data-flow tracing from source to sink; params: `source`, `sink`, `address`
- `findings` — List accumulated threat hunt findings; params: `category`, `severity`
- `quick` — Fast surface-level triage scan; params: `scope`
- `deep` — Deep recursive analysis with full call-graph traversal; params: `address`, `max_depth`
- `legacy` — Route legacy tool calls (vuln_scan, c2_detect, taint); params: `original_tool`, `original_action`

## Examples
```json
{"name": "threat_hunt", "arguments": {"action": "vuln", "address": "0x401000"}}
```
```json
{"name": "threat_hunt", "arguments": {"action": "quick", "scope": "all"}}
```

## Notes
- `vuln_scan` and `taint` are legacy aliases that route through this tool automatically.
- Use `findings` to retrieve results after `run`/`quick`/`deep` completes.
- Supports both function-scoped and binary-wide analysis via `scope` param.
