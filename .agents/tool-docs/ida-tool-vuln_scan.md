# IDA MCP Tool Doc: `vuln_scan`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `vuln_scan` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Automated vulnerability scanner. Actions: buffer_overflow, format_string, integer_overflow, use_after_free, command_injection, race_condition, null_deref, info_leak, auth_bypass, hardcoded_creds, scan_all, classify, osv_query. Returns compact findings + structured items with severity/confidence, pagination, and optional OSV enrichment.

## Actions
- `buffer_overflow` (tool-specific)
- `format_string` (tool-specific)
- `integer_overflow` (tool-specific)
- `use_after_free` (tool-specific)
- `command_injection` (tool-specific)
- `race_condition` (tool-specific)
- `null_deref` (tool-specific)
- `info_leak` (tool-specific)
- `auth_bypass` (tool-specific)
- `hardcoded_creds` (tool-specific)
- `scan_all` (tool-specific)
- `classify` (tool-specific)
- `osv_query` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/vuln_scan')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

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

## Minimal Call Shapes
```json
{
  "name": "vuln_scan",
  "arguments": {
    "action": "buffer_overflow"
  }
}
```
```json
{
  "name": "vuln_scan",
  "arguments": {
    "action": "grep",
    "source_action": "buffer_overflow",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
