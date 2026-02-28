# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`idb`

## Use This Skill When
- You need to call the `idb` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Database metadata and segment information. Actions: meta, summary, segments, entrypoints, bookmarks, overview.

## Actions
- `meta`
- `summary`
- `segments`
- `entrypoints`
- `bookmarks`
- `overview`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
