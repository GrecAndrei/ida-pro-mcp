# Documentation Map

This folder is the canonical documentation source for `ida-pro-mcp`.

## Active documentation

- `../README.md` — project overview, install, architecture, tool surface, runtime behavior
- `OPENCODE_SETUP.md` — OpenCode-specific configuration and skills
- `POLICY.md` — governance policy reference
- `TECHNICAL_REFERENCE.md` — implementation-level architecture and runtime details
- `TOOLS_REFERENCE.md` — generated tool/action/argument reference from
  `host.agent_operations.AGENT_OPERATIONS`
- `wiki/` — in-tool documentation consumed by the `wiki` MCP tool
  - `wiki/QuickStart.md` — concise operational quickstart
  - `wiki/INDEX.md` — index of available wiki topics (hand-authored)
  - `wiki/tools/*.md` — per-tool manuals (hand-authored)

## Regeneration

`TOOLS_REFERENCE.md` and the `.agents/skills/` skill files are generated from
`host.agent_operations.AGENT_OPERATIONS` by `scripts/generate_tool_skills.py`.
The wiki manuals are hand-authored. The installer's `--only skills` phase only
copies the pre-generated skills into place — it does **not** regenerate them.

After operation schemas or descriptions change:
```bash
python scripts/check_schema_integrity.py
python scripts/generate_tool_skills.py
ida-pro-mcp-install --only skills
```

## Recommended reading order

1. `../README.md`
2. `wiki/QuickStart.md`
3. `TOOLS_REFERENCE.md`
4. `TECHNICAL_REFERENCE.md`
