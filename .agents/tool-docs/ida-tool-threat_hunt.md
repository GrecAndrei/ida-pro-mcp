# IDA MCP Tool Doc: `threat_hunt`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `threat_hunt` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Consolidated malware/vulnerability/tracing/search-finding orchestration hub. Actions: run, malware, vuln, tracing, findings, quick, deep, legacy. Executes real end-to-end pipelines across existing tools and can route legacy actions from archived tools, returning step-by-step status with deduplicated findings.

## Actions
- `run` (tool-specific)
- `malware` (tool-specific)
- `vuln` (tool-specific)
- `tracing` (tool-specific)
- `findings` (tool-specific)
- `quick` (tool-specific)
- `deep` (tool-specific)
- `legacy` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/threat_hunt')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `run, malware, vuln, tracing, findings, quick, deep, legacy`
- `addr`: `string` - Optional address focus for underlying scanners where supported.
- `include_evidence`: `boolean` - Include compact raw per-step payloads for auditability.
- `include_malware`: `boolean` - Include malware-behavior analysis steps.
- `include_tracing`: `boolean` - Include trace/coverage analysis steps.
- `include_vuln`: `boolean` - Include vulnerability analysis steps.
- `legacy_action`: `string` - Legacy action to inherit/route (for action='legacy').
- `legacy_passthrough`: `boolean` - For action='legacy', execute exact mapped legacy action in consolidated flow and include mapping metadata.
- `legacy_tool`: `string` - Legacy tool name to emulate (for action='legacy').
- `limit`: `integer` - Global max findings to return after dedupe/ranking.
- `max_steps`: `integer` - Safety cap for total orchestrated tool calls.
- `profile`: `string` - allowed: `quick, balanced, deep` - Pipeline depth profile.
- `query`: `string` - Optional focus query for post-filtering and relevance scoring.
- `scan_profile`: `string` - allowed: `quick, balanced, deep` - Forwarded depth profile to threat_hunt.
- `severity`: `string` - allowed: `critical, high, medium, low` - Optional severity filter for vulnerability findings.
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "threat_hunt",
  "arguments": {
    "action": "run"
  }
}
```
```json
{
  "name": "threat_hunt",
  "arguments": {
    "action": "grep",
    "source_action": "run",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
