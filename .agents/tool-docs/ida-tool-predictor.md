# IDA MCP Tool Doc: `predictor`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `predictor` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Deterministic prediction of next useful tool, focus address, or stuck-state detection. recommend_bundle returns a bundled next-step pack (tools + focus + addresses + stall risk). Actions: suggest_next_tool, detect_stuck, suggest_focus, suggest_next_address, risk_of_stall, recommend_bundle.

## Actions
- `suggest_next_tool` (tool-specific)
- `detect_stuck` (tool-specific)
- `suggest_focus` (tool-specific)
- `suggest_next_address` (tool-specific)
- `risk_of_stall` (tool-specific)
- `recommend_bundle` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/predictor')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `suggest_next_tool, detect_stuck, suggest_focus, suggest_next_address, risk_of_stall, recommend_bundle`
- `context`: `string` - Optional context text to bias suggestions.
- `limit`: `integer` - Maximum suggestions to return.
- `outcome`: `string` - allowed: `helpful, not_helpful` - Feedback outcome for predictor(action='feedback').
- `recent_n`: `integer` - Recent activity window for sequence modeling.
- `session_id`: `string` - Optional session ID. If omitted, active session is used.
- `target_action`: `string` - Target action for explain_decision action.
- `target_tool`: `string` - Target tool for explain_decision action.
- `tool`: `string` - Tool name for predictor feedback action.
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "predictor",
  "arguments": {
    "action": "suggest_next_tool"
  }
}
```
```json
{
  "name": "predictor",
  "arguments": {
    "action": "grep",
    "source_action": "suggest_next_tool",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
