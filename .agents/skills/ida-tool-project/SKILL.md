# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`project`

## Use This Skill When
- You need to call the `project` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Project I/O and file operations. Actions: save, close, open, load_binary, list_recent, get_cwd, set_cwd, list_dir, exists. Legacy actions read/write map to misc read_file/write_file.

## Actions
- `save`
- `close`
- `open`
- `load_binary`
- `list_recent`
- `get_cwd`
- `set_cwd`
- `list_dir`
- `exists`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
