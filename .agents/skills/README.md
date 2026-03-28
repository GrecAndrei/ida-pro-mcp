# Generated IDA Tool Skills
<!-- GENERATED: scripts/generate_tool_skills.py -->

- Source: `ida_mcp_stdio.py` (`TOOL_DESCRIPTIONS`, `TOOL_ACTIONS`, `TOOL_ARG_SCHEMAS`)
- Generator: `scripts/generate_tool_skills.py`

## Regenerate
```bash
python3 scripts/generate_tool_skills.py
```

## Generated Skill Count
`1` router skill (`ida-tool-router`)

## Generated Tool Doc Count
`67` per-tool docs

## Notes
- Keep only one skill loaded (`ida-tool-router`) to avoid startup skill-list bloat.
- Per-tool docs are plain markdown in `.agents/tool-docs/` and loaded on demand.
- Edit source metadata in `ida_mcp_stdio.py`, then regenerate.

## Manifest
```json
{
  "tool_count": 67,
  "skills_root": ".agents/skills",
  "router_skill": ".agents/skills/ida-tool-router/SKILL.md",
  "tool_docs_root": ".agents/tool-docs"
}
```
