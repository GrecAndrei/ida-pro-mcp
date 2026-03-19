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
- `osv_query`: queries OSV (`api.osv.dev`) for known vulnerable package versions
- `intelligence_report`: scan-all + smarter risk scoring, hotspot clustering, and attack-path correlation

## Key Parameters
- `action`: One of the actions above.
- `addr`: Optional function/address scope for scans; required for `classify`.
- `limit`: Max returned findings.
- `offset`: Skip first N ranked findings.
- `severity`: Optional filter `critical|high|medium|low`.
- `include_context`: Adds compact decompiled context into structured items when available.
- `scan_profile`: Optional scan depth profile `quick|balanced|deep` controlling analysis/ranking rigor.
- `osv_coordinates`: List of coordinates in `ecosystem:name@version` or `pkg:purl` format.
- `osv_ecosystem`: Default ecosystem for shorthand coordinates like `name@version`.
- `osv_endpoint`: Optional OSV endpoint/base URL (defaults to `https://api.osv.dev`).

## Response Contract
- `findings`: Backward-compatible compact newline output.
- `items`: Structured findings with fields such as `addr`, `function`, `type`, `cwe`, `severity`, `confidence`, `description`, `pattern`, optional `context`.
- `count`, `total`, `offset`, `truncated`: Stable pagination metadata.
- `severity_counts`, `type_counts`: Aggregated triage summaries.
- `risk_histogram`: Distribution buckets for normalized risk scores.
- `hotspots`: Top risky functions with vulnerability density.
- `attack_paths`: Correlated multi-stage exploit chains (especially in `intelligence_report`).
- `recommendations`: Prioritized remediation guidance based on observed findings.

## Major Improvements
- API resolution now handles import variants (e.g. WinAPI `A/W`, decorated imports, `__imp_` prefixes) instead of exact-name only.
- Findings are now deduplicated and ranked by `severity` then `confidence` for more useful top results.
- `scan_all` gathers deeper candidate sets per scanner, then globally normalizes/ranks instead of naive concatenation.
- Findings now include normalized `risk_score`, `priority`, and `exploitability` for better triage ordering.
- New `scan_profile` (`quick|balanced|deep`) controls local evidence windows and scan intensity.
- New `intelligence_report` action correlates multiple finding classes into exploit-path chains and function hotspots.
- `scan_all` can optionally include OSV-enriched findings when `osv_coordinates` are provided.
- New `osv_query` action gives direct OSV-backed findings with the same normalized ranking/pagination contract.
- Severity filtering is now structural (not string-tag matching).
- `hardcoded_creds` now prefers assignment-style credential patterns (`key=value`, `key: value`) to reduce false positives.
- Several scanner loops were hardened for scope correctness and noise reduction.

## Examples
```json
{"name":"vuln_scan","arguments":{"action":"scan_all","limit":80,"severity":"high"}}
```

```json
{"name":"vuln_scan","arguments":{"action":"intelligence_report","scan_profile":"deep","limit":120}}
```

```json
{"name":"vuln_scan","arguments":{"action":"command_injection","addr":"0x401000","limit":25}}
```

```json
{"name":"vuln_scan","arguments":{"action":"classify","addr":"0x402120"}}
```

```json
{"name":"vuln_scan","arguments":{"action":"osv_query","osv_coordinates":["PyPI:requests@2.19.0","npm:lodash@4.17.20"]}}
```

## Failure Modes
- Invalid `severity` values are rejected.
- `classify` without `addr` is rejected.
- Unknown action returns invalid-args error.
- Pattern-based heuristics can produce false positives/negatives; always validate manually in disassembly/decompilation.
- `osv_query` requires valid package coordinates; malformed coordinates are returned in `parse_errors`.
- OSV network/API failures are reported in `osv_error` while preserving local scan results (for `scan_all`).
