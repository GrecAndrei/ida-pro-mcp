# VULN_SCAN Tool Manual

## What It Does
Runs heuristic static vulnerability scans and emits compact CWE-tagged findings suitable for triage.

## Actions
- `buffer_overflow` (CWE-120)
- `format_string` (CWE-134)
- `integer_overflow` (CWE-190)
- `use_after_free` (CWE-416)
- `command_injection` (CWE-78)
- `race_condition` (CWE-362)
- `null_deref` (CWE-476)
- `info_leak` (CWE-200)
- `auth_bypass` (CWE-287)
- `hardcoded_creds` (CWE-798)
- `scan_all`: runs all scanners and aggregates
- `classify`: runs all scanners around one address/function context

## Key Parameters
- `action`: One of the actions above.
- `addr`: Optional function/address scope for scans; required for `classify`.
- `limit`: Max returned findings.
- `severity`: Optional filter `critical|high|medium|low`.
- `include_context`: Accepted parameter; current output remains compact finding lines.

## Examples
```json
{"name":"vuln_scan","arguments":{"action":"scan_all","limit":80,"severity":"high"}}
```

```json
{"name":"vuln_scan","arguments":{"action":"command_injection","addr":"0x401000","limit":25}}
```

```json
{"name":"vuln_scan","arguments":{"action":"classify","addr":"0x402120"}}
```

## Failure Modes
- Invalid `severity` values are rejected.
- `classify` without `addr` is rejected.
- Unknown action returns invalid-args error.
- Pattern-based heuristics can produce false positives/negatives; always validate manually in disassembly/decompilation.
- Most findings are newline-joined strings (not structured per-field objects).
