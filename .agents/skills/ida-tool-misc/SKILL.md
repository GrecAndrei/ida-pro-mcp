# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`misc`

## Use This Skill When
- You need to call the `misc` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Utilities. Actions: python, idc, load_sig, cache_stats, read_file, write_file, plugin_list, plugin_run, health. Use python for full IDAPython access. read_file/write_file for host filesystem I/O. plugin_* manages IDA plugins. health runs host diagnostics without requiring a session.

## Actions
- `python`
- `idc`
- `load_sig`
- `cache_stats`
- `read_file`
- `write_file`
- `plugin_list`
- `plugin_run`
- `health`

## Parameters
- `action`: `string` - allowed: `python, idc, load_sig, cache_stats, read_file, write_file, plugin_list, plugin_run, health`
- `arg`: `integer` - Plugin argument for plugin_run
- `code`: `string` - Multi-line Python code to execute
- `content`: `string` - Content to write for write_file
- `encoding`: `string` - File encoding (default: utf-8). Use 'binary' for hex-encoded binary data.
- `expr`: `string` - Python expression or IDC script to evaluate
- `name`: `string` - Signature name for load_sig
- `path`: `string` - File path for read_file/write_file
- `verbose`: `boolean` - Include per-runtime details for health action.

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
