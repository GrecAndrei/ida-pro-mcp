# IDA MCP Tool Doc: `workflow`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `workflow` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Executes predefined multi-step analysis workflows for common RE tasks. audit_plan validates and scores a plan before execution. execute_plan runs a planned call list (or generated plan) through batch execution with execution metadata. prioritize reorders a dry-run plan by strategy (original/coverage/risk_first). compose merges multiple workflow plans into one deduplicated dry-run execution plan. estimate returns dry-run complexity/risk/category projections. explain returns a dry-run plan plus per-step rationale. plan previews another workflow action without executing it. catalog returns available workflows and required inputs. triage_fast auto-checks idb overview and, for firmware-like binaries, injects firmware_view(action='triage_snapshot') plus guided analysis. recon_sweep runs broader orientation + structured retrieval + protocol + security posture in one pass. Supports dry_run plan preview and include/exclude tool filtering for controlled orchestration. Actions: audit_plan, execute_plan, prioritize, compose, estimate, explain, plan, catalog, triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review.

## Actions
- `audit_plan` (tool-specific)
- `execute_plan` (tool-specific)
- `prioritize` (tool-specific)
- `compose` (tool-specific)
- `estimate` (tool-specific)
- `explain` (tool-specific)
- `plan` (tool-specific)
- `catalog` (tool-specific)
- `recon_sweep` (tool-specific)
- `triage_fast` (tool-specific)
- `malware_deep` (tool-specific)
- `vuln_audit` (tool-specific)
- `patch_review` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/workflow')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed_count: `13`
- `addr`: `string` - Optional address focus for the workflow.
- `continue_on_error`: `boolean` - For action='execute_plan': continue executing later calls when one call fails.
- `dry_run`: `boolean` - When true, return the planned calls and workflow metadata without executing tool steps.
- `exclude_tools`: `array|string` - Optional deny-list of tool names to remove from the generated plan.
- `include_tools`: `array|string` - Optional allow-list of tool names to keep in the generated plan.
- `limit`: `integer` - Max findings per sub-step.
- `max_steps`: `integer` - For action='execute_plan': maximum calls to execute from the provided/generated plan.
- `planned_calls`: `array` - For action='prioritize'/'execute_plan'/'audit_plan': optional dry-run call list to reorder, execute, or validate.
- `priority_mode`: `string` - allowed: `original, coverage, risk_first` - For action='prioritize': sorting strategy for dry-run plan ordering.
- `profile`: `string` - allowed: `quick, balanced, deep` - Depth profile override for underlying pipelines.
- `workflow_action`: `string` - For action='plan': target workflow action to preview (for example triage_fast or recon_sweep).
- `workflow_actions`: `array|string` - For action='compose': list of workflow actions to merge into one dry-run plan.
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "workflow",
  "arguments": {
    "action": "audit_plan"
  }
}
```
```json
{
  "name": "workflow",
  "arguments": {
    "action": "grep",
    "source_action": "audit_plan",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
