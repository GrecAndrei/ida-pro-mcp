# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`classify`

## Use This Skill When
- You need to call the `classify` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Function purpose classification. Actions: function, binary, all_functions, library_code, wrappers, callbacks, initializers, error_handlers, hot_functions, orphans.

## Actions
- `function`
- `binary`
- `all_functions`
- `library_code`
- `wrappers`
- `callbacks`
- `initializers`
- `error_handlers`
- `hot_functions`
- `orphans`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
