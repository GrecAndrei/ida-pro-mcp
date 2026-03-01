# IDA MCP Tool Doc: `llm_helpers`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `llm_helpers` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
LLM workflow helpers. Actions: context_window (token-budgeted context), function_digest, binary_digest, explain_address, suggest_next, progress_report, focus_area, question_answer, guided_analysis, cheatsheet.

## Actions
- `context_window`
- `function_digest`
- `binary_digest`
- `explain_address`
- `suggest_next`
- `progress_report`
- `focus_area`
- `question_answer`
- `guided_analysis`
- `cheatsheet`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
