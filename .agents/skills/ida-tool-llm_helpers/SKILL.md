# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`llm_helpers`

## Use This Skill When
- You need to call the `llm_helpers` tool.
- You want exact action/parameter contract without scanning global tool metadata.

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

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
