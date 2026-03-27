# THREAT_HUNT Tool Manual

## What It Does
Consolidated malware/vulnerability/tracing orchestration hub. Actions: run, malware, vuln, tracing, quick, deep. Executes real end-to-end pipelines across existing tools (vuln_scan, c2_detect, deobfuscate, crypto_id, trace_analysis, coverage, taint) and returns step-by-step status with deduplicated findings.

## Actions
- `run`
- `malware`
- `vuln`
- `tracing`
- `quick`
- `deep`

## Parameters
- `_compact`: `boolean` — Shortcut for compact/full mode toggle.
- `_error_details`: `string`; allowed: `none, basic, full` — Controls verbosity of error details.
- `_qol_mode`: `string`; allowed: `tiny, balanced, debug` — QoL profile shortcut for response compaction presets.
- `_response_batch_compact`: `boolean` — Compact batch envelopes in compact mode.
- `_response_char_budget`: `integer` — Approximate max output chars before truncation middleware applies.
- `_response_fields`: `array | string` — Optional top-level field projection (comma-separated string or list).
- `_response_max_items`: `integer` — Max list items retained in compact mode.
- `_response_max_string`: `integer` — Max string length retained in compact mode.
- `_response_mode`: `string`; allowed: `compact, full` — Output mode. compact is default and reduces token usage.
- `_response_omit`: `array | string` — Optional top-level field omission list.
- `_response_table`: `boolean` — Convert repetitive list-of-object payloads into {columns,rows}.
- `action`: `string`; allowed: `run, malware, vuln, tracing, quick, deep, grep, pick, head, tail, next, stats`
- `addr`: `string` — Optional address focus for underlying scanners where supported.
- `cursor`: `string`
- `grep`: `string` — Grep pattern (substring by default; regex if grep_regex=true).
- `grep_case_sensitive`: `boolean`
- `grep_field`: `string` — Optional top-level source field to grep (e.g. matches, functions, content).
- `grep_invert`: `boolean`
- `grep_limit`: `integer`
- `grep_offset`: `integer`
- `grep_pattern`: `string`
- `grep_regex`: `boolean`
- `head_n`: `integer`
- `idb`: `string` — Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.
- `include_evidence`: `boolean` — Include compact raw per-step payloads for auditability.
- `include_malware`: `boolean` — Include malware-behavior analysis steps.
- `include_tracing`: `boolean` — Include trace/coverage analysis steps.
- `include_vuln`: `boolean` — Include vulnerability analysis steps.
- `limit`: `integer` — Global max findings to return after dedupe/ranking.
- `max_steps`: `integer` — Safety cap for total orchestrated tool calls.
- `next_token`: `string`
- `on`: `string`
- `pick_fields`: `array | string` — For action='pick': top-level fields to include.
- `pick_omit`: `array | string` — For action='pick': top-level fields to omit after pick_fields.
- `profile`: `string`; allowed: `quick, balanced, deep` — Pipeline depth profile.
- `qol_mode`: `string`; allowed: `tiny, balanced, debug`
- `query`: `string` — Optional focus query for post-filtering and relevance scoring.
- `scan_profile`: `string`; allowed: `quick, balanced, deep` — Forwarded depth profile to vuln_scan.
- `severity`: `string`; allowed: `critical, high, medium, low` — Optional severity filter for vulnerability findings.
- `source_action`: `string` — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: `boolean`
- `subaction`: `string`
- `tail_n`: `integer`
- `target_action`: `string`
- `token`: `string`

## Example
```json
{
  "name": "threat_hunt",
  "arguments": {
    "action": "run"
  }
}
```

## Notes
- Consolidated end-to-end orchestration tool for malware/vulnerability/tracing workflows.
- Legacy threat tools may be routed through this tool for compatibility.

---
Doc status: Auto-generated from live tool metadata.
Last reviewed: 2026-03-27
