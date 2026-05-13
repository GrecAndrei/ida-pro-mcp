# yara_hunt

Compiles and scans YARA rules against the loaded binary, with cross-reference enrichment.

## Actions
- `compile` — Compile a YARA rule from string or file for validation; params: `rule`, `path`
- `scan` — Scan binary with YARA rules (inline string or file path); params: `rule`, `path`, `timeout`
- `list_rules` — List currently loaded/compiled rules
- `xref_matches` — Enrich YARA match offsets with IDA cross-references; params: `matches`, `address`

## Examples
```json
{"name": "yara_hunt", "arguments": {"action": "scan", "rule": "rule test { strings: $a = \"MZ\" condition: $a at 0 }"}}
```
```json
{"name": "yara_hunt", "arguments": {"action": "scan", "path": "/rules/apt_backdoor.yar"}}
```

## Notes
- Falls back to a built-in byte pattern scanner if `yara-python` is not installed.
- Use `xref_matches` after `scan` to map match addresses to functions and callers.
- Inline rules and file paths are both supported in `scan`.
