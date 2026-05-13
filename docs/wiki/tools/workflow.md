# workflow

Pre-built analysis workflow templates that orchestrate multiple tools in sequence.

## Actions
- `triage_fast` — quick binary triage (imports, strings, entry points, suspicious patterns)
- `malware_deep` — deep malware analysis workflow (unpacking, C2, persistence, evasion)
- `vuln_audit` — vulnerability audit (dangerous APIs, buffer handling, format strings)
- `patch_review` — review binary patches (diff against known-good, verify integrity)

## Examples
```json
{"name": "workflow", "arguments": {"action": "triage_fast"}}
```
```json
{"name": "workflow", "arguments": {"action": "vuln_audit"}}
```

## Notes
- Workflows run multiple tools internally and return consolidated results.
- `triage_fast` is the recommended first action on any new binary.
- Results are automatically written to the blackboard for later reference.
