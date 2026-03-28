# VULN_SCAN Tool Manual

## What It Does
Automated vulnerability scanner. Actions: buffer_overflow, format_string, integer_overflow, use_after_free, command_injection, race_condition, null_deref, info_leak, auth_bypass, hardcoded_creds, scan_all, classify, osv_query, intelligence_report. Supports scan_profile (quick|balanced|deep), optional dataflow graph/remediation planning, and returns ranked findings with risk scoring, hotspots, and attack-path correlation.

## Actions
- `buffer_overflow`
- `format_string`
- `integer_overflow`
- `use_after_free`
- `command_injection`
- `race_condition`
- `null_deref`
- `info_leak`
- `auth_bypass`
- `hardcoded_creds`
- `scan_all`
- `classify`
- `osv_query`
- `intelligence_report`

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
- `action`: `string`; allowed_count: `20`
- `addr`: `string` — Address or function scope for scanning.
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
- `include_context`: `boolean` — Include compact decompiled context when available.
- `include_dataflow_graph`: `boolean` — Include compact correlation graph in scan_all/intelligence_report.
- `include_remediation_plan`: `boolean` — Include prioritized remediation plan in scan_all/intelligence_report.
- `limit`: `integer` — Max findings to return (capped for context safety).
- `max_graph_depth`: `integer` — Correlation graph depth (0-3) for intelligence outputs.
- `next_token`: `string`
- `offset`: `integer` — Skip first N ranked findings.
- `on`: `string`
- `osv_coordinates`: `array` — OSV package coordinates (ecosystem:name@version or pkg:purl). Used by osv_query and optional scan_all enrichment.
- `osv_ecosystem`: `string` — Default OSV ecosystem for shorthand coordinates like name@version.
- `osv_endpoint`: `string` — OSV endpoint/base URL (default: https://api.osv.dev).
- `pick_fields`: `array | string` — For action='pick': top-level fields to include.
- `pick_omit`: `array | string` — For action='pick': top-level fields to omit after pick_fields.
- `qol_mode`: `string`; allowed: `tiny, balanced, debug`
- `scan_profile`: `string`; allowed: `quick, balanced, deep` — Scan depth profile controlling local evidence/ranking rigor.
- `severity`: `string`; allowed: `critical, high, medium, low` — Optional severity filter.
- `source_action`: `string` — For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).
- `stats_include_payload`: `boolean`
- `subaction`: `string`
- `tail_n`: `integer`
- `target_action`: `string`
- `token`: `string`

## Example
```json
{
  "name": "vuln_scan",
  "arguments": {
    "action": "buffer_overflow"
  }
}
```

## Notes
- `idb` is optional for most tools and resolves from active session when omitted.

---
Doc status: Auto-generated from live tool metadata.
Last reviewed: 2026-03-27
