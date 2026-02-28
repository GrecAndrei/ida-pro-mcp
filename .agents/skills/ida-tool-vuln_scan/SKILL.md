# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`vuln_scan`

## Use This Skill When
- You need to call the `vuln_scan` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Automated vulnerability scanner. Actions: buffer_overflow, format_string, integer_overflow, use_after_free, command_injection, race_condition, null_deref, info_leak, auth_bypass, hardcoded_creds, scan_all, classify, osv_query. Returns compact findings + structured items with severity/confidence, pagination, and optional OSV enrichment.

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

## Parameters
- `action`: `string` - allowed_count: `13`
- `addr`: `string` - Address or function scope for scanning.
- `include_context`: `boolean` - Include compact decompiled context when available.
- `limit`: `integer` - Max findings to return (capped for context safety).
- `offset`: `integer` - Skip first N ranked findings.
- `osv_coordinates`: `array` - OSV package coordinates (ecosystem:name@version or pkg:purl). Used by osv_query and optional scan_all enrichment.
- `osv_ecosystem`: `string` - Default OSV ecosystem for shorthand coordinates like name@version.
- `osv_endpoint`: `string` - OSV endpoint/base URL (default: https://api.osv.dev).
- `severity`: `string` - allowed: `critical, high, medium, low` - Optional severity filter.

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
