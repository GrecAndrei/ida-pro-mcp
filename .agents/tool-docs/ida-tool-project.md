# IDA MCP Tool Doc: `project`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `project` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

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
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
