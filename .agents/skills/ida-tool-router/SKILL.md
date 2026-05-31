---
name: "ida-tool-router"
description: "Use to select the correct per-tool IDA MCP tool doc and avoid loading all tool docs at once."
metadata:
  short-description: "Route to one tool skill"
---

# IDA MCP Tool Router Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
Load only one tool doc at a time to keep context small.

## How To Use
- Identify the intended tool name from the user request.
- Open only `.agents/tool-docs/ida-tool-<tool>.md` for that tool.
- Avoid opening unrelated tool docs to keep context small.

## Resolution Rules
- Default doc filename: `ida-tool-<tool>.md`
- Example: tool `search` -> `.agents/tool-docs/ida-tool-search.md`
- If unsure, list docs under `.agents/tool-docs/` and pick exact match.

## Available Tool Count
- `73`
