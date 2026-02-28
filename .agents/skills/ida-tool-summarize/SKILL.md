# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`summarize`

## Use This Skill When
- You need to call the `summarize` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
LLM-friendly summarization with compact output. Actions: binary, function, segment, imports_by_category, strings_by_category, complexity, call_hierarchy, data_flow, security_posture, statistics.

## Actions
- `binary`
- `function`
- `segment`
- `imports_by_category`
- `strings_by_category`
- `complexity`
- `call_hierarchy`
- `data_flow`
- `security_posture`
- `statistics`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
