# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`patterns`

## Use This Skill When
- You need to call the `patterns` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Signature and pattern matching. Actions: generate, match, list_sigs, apply_sig, create_sig.

## Actions
- `generate`
- `match`
- `list_sigs`
- `apply_sig`
- `create_sig`
- `matched`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
